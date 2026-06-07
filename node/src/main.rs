use bitcoin::consensus::encode::deserialize;
use bitcoin::Network;
use clap::Parser;
use futures::lock::Mutex;
use futures::StreamExt;
use libp2p::kad::BootstrapOk;
use libp2p::{
    core::multiaddr::Multiaddr,
    floodsub::{self},
    identify,
    identity::Keypair,
    kad::{self, Mode, QueryResult},
    ping, request_response,
    swarm::SwarmEvent,
    PeerId,
};
use node::db::db_handlers::fetch_beads_in_batch;
use node::sync::{ingest_beads, RetryPolicy, SyncAction, SyncEngine, SyncEvent, IBD_HASH_PAGE_MAX};
use node::utils::BeadHash;
use node::SwarmHandler;
use node::{
    bead::{Bead, BeadHashes, BeadRequest, BeadResponse, BeadSyncError},
    behaviour::{self, BEAD_ANNOUNCE_PROTOCOL, BRAIDPOOL_TOPIC},
    braid, cli,
    db::db_handlers::DBHandler,
    ipc_template_consumer,
    peer_manager::PeerManager,
    rpc_server::{run_rpc_server, BitcoinRpcConfig, RpcProxyCommand},
    setup_tracing,
    stratum::{BlockTemplate, ConnectionMapping, Notifier, NotifyCmd, Server, StratumServerConfig},
    SwarmCommand, TemplateId,
};
use std::collections::HashSet;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{collections::HashMap, error::Error};
use std::{fs, time::Duration};
use tokio_util::sync::CancellationToken;
#[allow(unused_imports)]
use tracing::{debug, error, info, trace, warn};

use behaviour::{BraidPoolBehaviour, BraidPoolBehaviourEvent};

use crate::behaviour::KADPROTOCOLNAME;
/// Minimum number of connected peers before IBD is triggered.
const MIN_PEERS_FOR_IBD: usize = 1;
/// Delay (seconds) before the initial IBD kickstart attempt after startup.
const IBD_TRIGGER_AFTER: u64 = 20;
//boot nodes peerIds
const BOOTNODES: [&str; 1] = ["12D3KooWG9z8TziaNuYyEcc9FeUC3FTtrEf2XSnSdDpLvx4Jh2w3"];
//dns NS
const SEED_DNS: &str = "/dnsaddr/french.braidpool.net";
//combined addr for dns resolution and dialing of boot for peer discovery
const ADDR_REFRENCE: &str =
    "/dnsaddr/french.braidpool.net/p2p/12D3KooWG9z8TziaNuYyEcc9FeUC3FTtrEf2XSnSdDpLvx4Jh2w3";
use tokio::sync::{
    mpsc::{self},
    RwLock,
};
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize tracing with colors and module prefixes
    setup_tracing()?;
    let args = cli::Cli::parse();
    //True while the node is performing IBD; cleared (false) by the IBD engine's
    //`MarkComplete` action. Gates downstream (miner) connections via stratum.
    let ibd_spinlock = Arc::new(AtomicBool::new(true));
    // Initializing the braid object with read write lock
    //for supporting concurrent readers and single writer
    let braid: Arc<RwLock<braid::Braid>> = Arc::new(RwLock::new(braid::Braid::new(Vec::from([]))));
    //Initializing DB and db command handler
    let (mut _db_handler, db_tx) = DBHandler::new().await.map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Database initialization failed: {:?}", e),
        )
    })?;
    let db_connection_pool = _db_handler.db_connection_pool.clone();
    //Reconstructing local braid upon startup
    let db_connection_pool_ref = _db_handler.db_connection_pool.clone();
    let braid_ref = braid.clone();
    // FIXME instead we should look 144 blocks back from the bitcoin tip (1 day) and load beads
    // starting from that block as genesis
    let initial_bead_fetch_handle = tokio::spawn(async move {
        let mut guard = braid_ref.write().await;
        let fetched_beads = fetch_beads_in_batch(&db_connection_pool_ref, 50).await?;
        info!(beads = fetched_beads.len(), "Beads loaded from DB");
        for bead in &fetched_beads {
            let curr_bead_status = guard.extend(&bead);
            info!(
                hash = ?bead.block_header.block_hash(),
                status = ?curr_bead_status,
                "Bead inserted"
            );
        }
        Ok::<(), node::error::DBErrors>(())
    });
    match initial_bead_fetch_handle.await {
        Ok(Ok(())) => {
            info!("Initial bead fetch completed successfully");
        }
        Ok(Err(e)) => {
            error!(error = ?e, "Failed to fetch beads from DB during startup");
            return Err(format!("Database bead fetch failed: {:?}", e).into());
        }
        Err(e) => {
            error!(error = ?e, "Initial bead fetch task panicked");
            return Err(format!("Initial bead fetch task panicked: {}", e).into());
        }
    }
    let latest_template_id = Arc::new(Mutex::new(TemplateId::default()));
    let latest_template_id_for_notifier = latest_template_id.clone();
    let latest_template_id_for_consumer = latest_template_id.clone();
    //Starting the `query_handler` task
    tokio::spawn(async move {
        let _res = _db_handler.insert_query_handler().await;
    });
    // Initializing the peer manager (shared between swarm and RPC server)
    // Using RwLock to allow concurrent reads (RPC server) while swarm handler can write
    let peer_manager_arc = Arc::new(tokio::sync::RwLock::new(PeerManager::new(8)));

    //One will go into the IPC and the other will go to the `notifier`
    let (notification_tx, notification_rx) = mpsc::channel::<NotifyCmd>(1024);
    //latest available template to be cached for the newest connection until new job is received
    let latest_template = Arc::new(Mutex::new(BlockTemplate::default()));

    //latest available template merkle branch
    let latest_template_merkle_branch = Arc::new(Mutex::new(Vec::new()));
    let mut latest_template_ref = latest_template.clone();
    let mut latest_template_merkle_branch_ref = latest_template_merkle_branch.clone();
    let ipc_socket_path_for_blocking = args.ipc_socket.clone();

    let notification_tx_for_ipc = notification_tx.clone();
    let latest_template_for_ipc = latest_template.clone();
    let latest_template_merkle_branch_for_ipc = latest_template_merkle_branch.clone();

    //Connection mapping for all the downstream connection connected to the stratum server
    let connection_mapping = Arc::new(tokio::sync::RwLock::new(ConnectionMapping::new()));
    // Clone connection_mapping for RPC server before it's used in async move blocks
    let connection_mapping_for_rpc = Arc::clone(&connection_mapping);
    // Create RPC proxy command channel - sender goes to RPC server, receiver goes to IPC handler
    let (rpc_proxy_tx, rpc_proxy_rx) = tokio::sync::mpsc::unbounded_channel::<RpcProxyCommand>();
    // peer_manager_arc is created above and shared between swarm and RPC server
    //spawning the rpc server
    let rpc_addr = args.rpc_bind.to_string();
    let bitcoin_rpc_config = BitcoinRpcConfig::from_cli_args(&args).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });

    let rpc_braid = Arc::clone(&braid);
    let rpc_peer_manager = peer_manager_arc.clone();
    let rpc_connection_mapping = connection_mapping_for_rpc.clone();
    let rpc_latest_template = latest_template.clone();
    let server_join = tokio::spawn(async move {
        run_rpc_server(
            rpc_braid,
            &rpc_addr,
            rpc_peer_manager,
            rpc_connection_mapping,
            rpc_latest_template,
            rpc_proxy_tx,
            bitcoin_rpc_config,
        )
        .await
    });
    let (_rpc_addr, dashboard_notifier) = match server_join.await {
        Ok(Ok(tuple)) => tuple,
        Ok(Err(())) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "RPC server startup failed",
            )
            .into());
        }
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("RPC server task failed: {}", e),
            )
            .into());
        }
    };
    //Communication bridge between stratum and network swarm and swarm commands also, for communicating share population and propogating them further
    let (swarm_handler, mut swarm_command_receiver) = SwarmHandler::new(
        Arc::clone(&braid),
        db_tx.clone(),
        Arc::clone(&dashboard_notifier),
    );

    //Swarm command sender
    let swarm_command_sender = swarm_handler.command_sender.clone();
    let swarm_handler_arc = Arc::new(Mutex::new(swarm_handler));
    //cloning the channel to be sent across different interfaces
    let notification_tx_clone = notification_tx.clone();
    //Mining job map keeping all the jobs provided to the downstream
    let mining_job_map = Arc::new(Mutex::new(HashMap::new()));
    //Intializing `notifier` for mining.notify
    let mut notifier: Notifier = Notifier::new(notification_rx, Arc::clone(&mining_job_map));
    //Stratum configuration initialization
    let stratum_config = StratumServerConfig {
        port: args.stratum_port,
        ..StratumServerConfig::default()
    };
    let (block_submission_tx, block_submission_rx) =
        tokio::sync::mpsc::unbounded_channel::<node::stratum::BlockSubmissionRequest>();
    //IBD notifier task after peer_discovery
    let swarm_command_sender_ref = swarm_command_sender.clone();
    let _ibd_trigger_handler = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(IBD_TRIGGER_AFTER)).await;
        //Sending IBD initiating command
        match swarm_command_sender_ref
            .send(SwarmCommand::InitiateIBD)
            .await
        {
            Ok(_) => {
                info!("IBD trigger sent");
            }
            Err(error) => {
                error!(error=?error,"An error occurred while initiating IBD after waiting for peer discovery - ");
            }
        };
    });
    //Initializing stratum server
    let mut stratum_server = Server::new(
        stratum_config,
        connection_mapping.clone(),
        Some(block_submission_tx),
    );
    //Running the notification service
    tokio::spawn(async move {
        let _res = notifier
            .run_notifier(
                connection_mapping.clone(),
                &mut latest_template_ref,
                &mut latest_template_merkle_branch_ref,
                latest_template_id_for_notifier,
            )
            .await;
    });
    //Running the stratum service
    let spin_lock_ref = ibd_spinlock.clone();
    tokio::spawn(async move {
        let _res = stratum_server
            .run_stratum_service(
                mining_job_map,
                notification_tx_clone,
                swarm_handler_arc.clone(),
                spin_lock_ref,
                None,
            )
            .await;
    });

    let (main_shutdown_tx, _main_shutdown_rx) =
        mpsc::channel::<tokio::signal::unix::SignalKind>(32);
    let main_task_token = CancellationToken::new();
    let ipc_task_token = main_task_token.clone();
    let datadir_str = args.datadir.to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid datadir path encoding",
        )
    })?;
    let datadir = shellexpand::full(datadir_str).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Shell expansion failed: {}", e),
        )
    })?;
    match fs::metadata(&*datadir) {
        Ok(m) => {
            if !m.is_dir() {
                error!(datadir = %datadir, "Data directory exists but is not a directory");
            }
            info!(datadir = %datadir, "Using existing data directory");
        }
        Err(_) => {
            info!(datadir = %datadir, "Creating data directory");
            fs::create_dir_all(&*datadir)?;
        }
    }

    let datadir_path = Path::new(&*datadir);
    let keystore_path = datadir_path.join("keystore");
    #[cfg(unix)]
    {
        if keystore_path.exists() {
            let perms = fs::metadata(&keystore_path)?.permissions();
            if perms.mode() & 0o777 != 0o400 {
                warn!(
                    permissions = perms.mode() & 0o777,
                    "Keystore permissions are not secure, setting to 0o400"
                );
                let mut new_perms = perms.clone();
                new_perms.set_mode(0o400);
                fs::set_permissions(&keystore_path, new_perms)?;
            }
        }
    }
    let keypair = match fs::read(&keystore_path) {
        Ok(keypair) => {
            info!(path = %keystore_path.display(), "Loading keypair from keystore");
            libp2p::identity::Keypair::from_protobuf_encoding(&keypair).map_err(|e| {
                error!(error = %e, path = %keystore_path.display(), "Failed to read keypair from keystore");
                e
            })?
        }
        Err(_) => {
            info!(path = %keystore_path.display(), "Generating new keypair");
            let keypair: Keypair = libp2p::identity::Keypair::generate_ed25519();
            let keypair_bytes = keypair.to_protobuf_encoding()?;
            fs::write(&keystore_path, keypair_bytes)?;
            #[cfg(unix)]
            {
                let mut perms = fs::metadata(&keystore_path)?.permissions();
                perms.set_mode(0o400);
                fs::set_permissions(&keystore_path, perms)?;
                info!(path = %keystore_path.display(), perms = "0o400", "Set keystore permissions");
            }
            keypair
        }
    };
    // load beads from db (if present) and insert in braid here
    // Initializing the peer manager (shared between swarm and RPC server)
    // Using RwLock to allow concurrent reads (RPC server) while swarm handler can write
    let peer_manager_arc = Arc::new(tokio::sync::RwLock::new(PeerManager::new(8)));
    //For local testing uncomment this keypair peer since it running to process will
    //result in same peerID leading to OutgoingConnectionError
    // let keypair = identity::Keypair::generate_ed25519();
    //creating a main topic subscribing to the current test topic
    let current_broadcast_topic: floodsub::Topic = floodsub::Topic::new(BRAIDPOOL_TOPIC);

    let swarm_builder = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_quic()
        .with_dns()
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("DNS setup failed: {:?}", e),
            )
        })?;
    // Note: with_behaviour closure must return behaviour directly (not Result), using expect for clear error message
    let mut swarm = swarm_builder
        .with_behaviour(|local_key| {
            BraidPoolBehaviour::new(local_key).expect(
                "Failed to create BraidPoolBehaviour - check keypair and network configuration",
            )
        })?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX)))
        .build();
    let socket_addr: std::net::SocketAddr = match args.bind.parse() {
        Ok(addr) => addr,
        Err(_) => format!("{}:6680", args.bind).parse().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Failed to parse bind address: {}", e),
            )
        })?,
    };
    let multi_addr: Multiaddr = format!(
        "/ip4/{}/udp/{}/quic-v1",
        socket_addr.ip(),
        socket_addr.port()
    )
    .parse()
    .map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Failed to create multiaddress: {}", e),
        )
    })?;
    //subscribing to the braidpool topic for broadcasting bead_found and other peer_communications belonging to a particular topic
    swarm
        .behaviour_mut()
        .bead_announce
        .subscribe(current_broadcast_topic.clone());
    //setting the server mode for the kademlia apart from the server
    swarm.behaviour_mut().kademlia.set_mode(Some(Mode::Server));

    //adding the boot nodes for peer discovery
    swarm.listen_on(multi_addr.clone())?;
    for boot_peer in BOOTNODES {
        let peer_id = match boot_peer.parse::<PeerId>() {
            Ok(id) => id,
            Err(e) => {
                error!(boot_peer = %boot_peer, error = %e, "Failed to parse boot peer ID, skipping");
                continue;
            }
        };
        let seed_addr = match SEED_DNS.parse::<Multiaddr>() {
            Ok(addr) => addr,
            Err(e) => {
                error!(seed_dns = %SEED_DNS, error = %e, "Failed to parse seed DNS, skipping");
                continue;
            }
        };
        swarm
            .behaviour_mut()
            .kademlia
            .add_address(&peer_id, seed_addr);
    }
    info!(boot_node_count = %BOOTNODES.len(), "Boot nodes added to DHT");
    let boot_addr: Multiaddr = ADDR_REFRENCE.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Failed to parse boot address: {}", e),
        )
    })?;
    swarm.dial(boot_addr)?;
    info!(address = %ADDR_REFRENCE, "Dialed boot node");
    // IPC(inter process communication) based `getblocktemplate` and `notification` to send to the downstream via the `cmempoold` architecture
    info!(socket = %args.ipc_socket, "IPC socket path");

    let network = if let Some(network_name) = &args.network {
        info!(network = %network_name, "Network selected");
        match network_name.as_str() {
            "main" | "mainnet" => Network::Bitcoin,
            "testnet" | "testnet4" => Network::Testnet(bitcoin::TestnetVersion::V4),
            "signet" => Network::Signet,
            "regtest" => Network::Regtest,
            // "cpunet" => Network::CPUNet,
            _ => {
                error!(
                    network = %network_name,
                    valid_networks = "main, testnet, testnet4, signet, regtest, cpunet",
                    "Invalid network specified"
                );
                info!(fallback = "regtest", "Using fallback network");
                Network::Regtest
            }
        }
    } else {
        Network::Bitcoin
    };

    // Spawn IPC handler
    let _ipc_handler = tokio::task::spawn_blocking(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                error!(error = %e, "Failed to create tokio runtime for IPC handler");
                return;
            }
        };
        rt.block_on(async {
            let local_set = tokio::task::LocalSet::new();

            local_set
                .run_until(async {
                    let template_cache: Arc<
                        tokio::sync::Mutex<
                            HashMap<TemplateId, Arc<node::ipc::client::BlockTemplate>>,
                        >,
                    > = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
                    let template_cache_for_consumer = template_cache.clone();
                    let template_cache_for_listener = template_cache.clone();
                    let (ipc_template_tx, ipc_template_rx) =
                        tokio::sync::mpsc::channel::<Arc<node::ipc::client::BlockTemplate>>(1);

                    let listener_task = tokio::task::spawn_local({
                        let ipc_socket_path = ipc_socket_path_for_blocking.clone();
                        let ipc_template_tx = ipc_template_tx.clone();
                        let template_cache = template_cache_for_listener.clone();
                        let rpc_command_rx = rpc_proxy_rx;

                        async move {
                            match node::ipc::ipc_block_listener(
                                ipc_socket_path,
                                ipc_template_tx,
                                network,
                                template_cache,
                                block_submission_rx,
                                rpc_command_rx,
                            )
                            .await
                            {
                                Ok(_) => {
                                    info!("IPC block listener exited");
                                }
                                Err(e) => {
                                    error!(error = %e, "IPC block listener error");
                                }
                            }
                        }
                    });

                    let consumer_task = tokio::task::spawn_local({
                        async move {
                            if let Err(e) = ipc_template_consumer(
                                ipc_template_rx,
                                notification_tx_for_ipc,
                                &mut latest_template_for_ipc.clone(),
                                &mut latest_template_merkle_branch_for_ipc.clone(),
                                template_cache_for_consumer,
                                latest_template_id_for_consumer,
                            )
                            .await
                            {
                                error!(error = ?e, "IPC template consumer error");
                            }
                        }
                    });

                    tokio::select! {
                        _ = listener_task => info!(task = "listener", "IPC listener task completed"),
                        _ = consumer_task => info!(task = "consumer", "Template consumer task completed"),
                        _ = ipc_task_token.cancelled() => {
                            info!("IPC task shutting down - cancellation token triggered");
                        }
                    }
                })
                .await;
        });
    });

    if let Some(addnode) = args.addnode {
        for node in addnode.iter() {
            let node_multiaddr: Multiaddr = match node.parse() {
                Ok(addr) => addr,
                Err(e) => {
                    error!(node = %node, error = %e, "Failed to parse multiaddr, skipping");
                    continue;
                }
            };
            let dial_result = swarm.dial(node_multiaddr.clone());
            if let Some(err) = dial_result.err() {
                error!(address = %node_multiaddr, error = %err, "Failed to dial peer node");
                continue;
            }
            info!(address = %node_multiaddr, "Dialed peer node");
        }
    };
    let peer_manager_arc_for_swarm = peer_manager_arc.clone();
    let swarm_handle = tokio::spawn(async move {
        let braid = std::sync::Arc::clone(&braid);
        let peer_manager_arc = peer_manager_arc_for_swarm;

        let mut sync_engine = SyncEngine::new(RetryPolicy::default());
        let mut ibd_inflight: Option<(PeerId, libp2p::request_response::OutboundRequestId)> = None;
        let mut ibd_initiated = false;
        loop {
            let mut sync_event: Option<SyncEvent> = None;
            tokio::select! {
             swarm_event = swarm.select_next_some()=>{
                 match swarm_event{
                     SwarmEvent::Behaviour(BraidPoolBehaviourEvent::Kademlia(
                         kad::Event::RoutingUpdated {
                             peer,
                             is_new_peer,
                             addresses,
                             bucket_range,
                             old_peer,
                         },
                     )) => {
                         info!(
                             peer = %peer,
                             is_new = %is_new_peer,
                             addresses = ?addresses,
                             bucket = ?bucket_range,
                             old_peer = ?old_peer,
                             "DHT routing updated"
                         );
                     }
                     SwarmEvent::Behaviour(BraidPoolBehaviourEvent::BeadAnnounce(
                         floodsub::FloodsubEvent::Subscribed { peer_id, topic },
                     )) => {
                         info!(
                             peer = ?peer_id,
                             topic = ?topic,
                             "Peer subscribed to topic"
                         );
                     }
                     SwarmEvent::Behaviour(BraidPoolBehaviourEvent::BeadAnnounce(
                         floodsub::FloodsubEvent::Unsubscribed { peer_id, topic },
                     )) => {
                         info!(
                             peer = ?peer_id,
                             topic = ?topic,
                             "Peer unsubscribed from topic"
                         );
                     }
                     SwarmEvent::Behaviour(BraidPoolBehaviourEvent::BeadAnnounce(
                         floodsub::FloodsubEvent::Message(message),
                     )) => {
                         debug!(source = ?message.source, size_bytes = %message.data.len(), "Floodsub bead received");
                         match deserialize::<Bead>(&message.data) {
                             Ok(bead) => {
                                 let outcome = {
                                     let mut braid_data = braid.write().await;
                                     ingest_beads(&mut braid_data, &[bead])
                                 };
                                 let (added, invalid) = (outcome.added, outcome.invalid);
                                 if let Some(cmd) = outcome.into_db_command() {
                                     if let Err(error) = db_tx.send(cmd).await {
                                         error!(err = ?error.0, source = ?message.source, "Failed to persist flooded bead");
                                     }
                                 }
                                 if added > 0 || invalid > 0 {
                                     let mut peer_manager = peer_manager_arc.write().await;
                                     for _ in 0..invalid {
                                         peer_manager.penalize_for_invalid_bead(&message.source);
                                     }
                                     if added > 0 {
                                         peer_manager.update_score(&message.source, added as f64);
                                     }
                                 }
                             }
                             Err(e) => {
                                 error!(error = %e, "Failed to deserialize flooded bead");
                             }
                         }
                     }
                     SwarmEvent::NewListenAddr { address, .. } => {
                         info!(address = ?address, "P2P listening on address")
                     }
                     SwarmEvent::Behaviour(BraidPoolBehaviourEvent::Identify(
                         identify::Event::Sent { peer_id, .. },
                     )) => {
                         debug!(peer = ?peer_id, "Sent identify info");
                     }
                     SwarmEvent::Behaviour(BraidPoolBehaviourEvent::Identify(
                         identify::Event::Received { peer_id, info,  .. },
                     )) => {
                         let info_reference = info.clone();
                         info!(
                             peer = ?peer_id,
                             address_count = %info_reference.listen_addrs.len(),
                             "Received listen addresses"
                         );
                         if info.protocols.iter().any(|p| *p == KADPROTOCOLNAME) {
                             for addr in info.listen_addrs {
                                 info!(address = %addr, "Received address via identify");
                             }
                         } else {
                             info!(peer = ?peer_id, "Peer does not support Kademlia");
                         }
                         if info_reference
                             .clone()
                             .protocols
                             .iter()
                             .any(|p| *p != BEAD_ANNOUNCE_PROTOCOL)
                         {

                             info!(
                                 peer_address = ?info_reference.observed_addr,
                                 "Peer does not support floodsub"
                             );
                         }
                         debug!(info = ?info_reference, "Received peer info");
                     }
                     SwarmEvent::Behaviour(BraidPoolBehaviourEvent::Kademlia(
                         kad::Event::OutboundQueryProgressed { result, .. },
                     )) => match result {
                         QueryResult::GetClosestPeers(Ok(ok)) => {
                             info!(peers = ?ok.peers, peer_count = %ok.peers.len(), "Got closest peers");
                         }
                         QueryResult::GetClosestPeers(Err(err)) => {
                             error!(error = %err, "Failed to get closest peers");
                         }
                        QueryResult::Bootstrap(Ok(BootstrapOk {
                            peer, ..
                        }))=>{
                            info!(peer = ?peer, "New peer");
                        }
                         _ => info!(result = ?result, "Other DHT query result"),
                     },
                     SwarmEvent::Behaviour(BraidPoolBehaviourEvent::Identify(
                         identify::Event::Error {
                             peer_id,
                             error,
                             connection_id: _,
                         },
                     )) => {
                         error!(peer = %peer_id, error = ?error, "Identify event error");
                     }
                     SwarmEvent::Behaviour(BraidPoolBehaviourEvent::Ping(ping::Event {
                         peer,
                         result,
                         ..
                     })) => {
                         match result {
                             Ok(latency) => {
                                 info!(
                                     peer = %peer,
                                     latency_ms = %latency.as_millis(),
                                     "Ping"
                                 );
                                {
                                    let mut peer_manager = peer_manager_arc.write().await;
                                    peer_manager.update_latency(&peer,latency);
                                }
                             }
                             Err(err) => {
                                 warn!(
                                     peer = %peer,
                                     error = %err,
                                     "Ping failed"
                                 );
                             }
                         }
                     }
                     SwarmEvent::ConnectionEstablished {
                         peer_id, endpoint, ..
                     } => {

                         // Add the peer to the peer manager
                         let remote_addr = endpoint.get_remote_address();
                         swarm.behaviour_mut().kademlia.add_address(&peer_id,remote_addr.clone());
                         info!(address = ?remote_addr, "DHT updated with peer address");
                         swarm.behaviour_mut()
                         .bead_announce
                         .add_node_to_partial_view(peer_id);

                         info!(peer = %peer_id, "Peer added to floodsub mesh");
                         let ip = remote_addr.iter().find_map(|p| match p {
                             libp2p::core::multiaddr::Protocol::Ip4(ip) => {
                                 Some(std::net::IpAddr::V4(ip))
                             }
                             libp2p::core::multiaddr::Protocol::Ip6(ip) => {
                                 Some(std::net::IpAddr::V6(ip))
                             }
                             _ => None,
                         });
                         {
                             let mut peer_manager = peer_manager_arc.write().await;
                             peer_manager.add_peer(peer_id, !endpoint.is_dialer(), ip);
                         }
                         info!(
                            peer_id = ?peer_id,
                            remote_addr = ?remote_addr,
                            "Connection established to peer"
                        );
                        // Trigger IBD once the connected-peer threshold is reached
                        {
                            let connected = peer_manager_arc.read().await.num_connected_peers();
                            if !ibd_initiated && connected >= MIN_PEERS_FOR_IBD {
                                ibd_initiated = true;
                                info!(connected, threshold = MIN_PEERS_FOR_IBD, "Peer threshold reached, initiating IBD");
                                if let Err(error) = swarm_command_sender.send(SwarmCommand::InitiateIBD).await {
                                    error!(error = ?error, "Failed to send IBD initiation command");
                                }
                            }
                        }
                     }
                     SwarmEvent::ConnectionClosed {
                         peer_id,
                         connection_id,
                         endpoint,
                         num_established,
                         cause,
                     } => {
                         info!(peer = %peer_id, connection_id = %connection_id, address = %endpoint.get_remote_address(), established = %num_established, cause = ?cause, "Connection closed");
                         // Remove the peer from the peer manager
                         {
                             let mut peer_manager = peer_manager_arc.write().await;
                             peer_manager.remove_peer(&peer_id);
                         }
                         swarm
                             .behaviour_mut()
                             .kademlia
                             .remove_address(&peer_id, endpoint.get_remote_address());
                         if ibd_inflight.map(|(p, _)| p) == Some(peer_id) {
                             ibd_inflight = None;
                             sync_event = Some(SyncEvent::PeerDisconnected { peer: peer_id });
                         }
                     }
                     SwarmEvent::Behaviour(BraidPoolBehaviourEvent::BeadSync(
                        request_response::Event::Message { peer, message, connection_id },
                    )) => {
                        debug!(peer = %peer, connection = ?connection_id, "Bead sync message received");
                        match message {
                            request_response::Message::Request { request, channel, .. } => {
                                match request {
                                    BeadRequest::GetBeads(hashes) => {
                                        let mut beads = Vec::new();
                                        {
                                            let braid_lock = braid.read().await;
                                            for hash in hashes.iter() {
                                                if let Some(&(index, _)) = braid_lock.bead_index_mapping.get(hash) {
                                                    if let Some(bead) = braid_lock.beads.get(index) {
                                                        beads.push(bead.clone());
                                                    }
                                                }
                                            }
                                        }
                                        swarm.behaviour_mut().respond_with_beads(channel, beads);
                                    }
                                    BeadRequest::GetTips => {
                                        let tips = {
                                            let braid_lock = braid.read().await;
                                            braid_lock.tips.iter()
                                                .filter_map(|index| braid_lock.beads.get(*index))
                                                .map(|bead| bead.block_header.block_hash())
                                                .collect()
                                        };
                                        swarm.behaviour_mut().respond_with_tips(channel, tips);
                                    }
                                    BeadRequest::GetGenesis => {
                                        let genesis = {
                                            let braid_lock = braid.read().await;
                                            braid_lock.genesis_beads.iter()
                                                .filter_map(|index| braid_lock.beads.get(*index))
                                                .map(|bead| bead.block_header.block_hash())
                                                .collect()
                                        };
                                        swarm.behaviour_mut().respond_with_genesis(channel, genesis);
                                    }
                                    BeadRequest::GetAllBeads => {
                                        let all_beads = { braid.read().await.beads.clone() };
                                        swarm.behaviour_mut().respond_with_beads(channel, all_beads);
                                    }
                                    BeadRequest::GetBeadsAfter(hashes) => {
                                        let beads = braid.read().await.get_beads_after(hashes.into(), IBD_HASH_PAGE_MAX);
                                        let computed: Vec<BeadHash> = beads
                                            .unwrap_or_default()
                                            .into_iter()
                                            .map(|bead| bead.block_header.block_hash())
                                            .collect();
                                        swarm.behaviour_mut().respond_with_beadhashes(channel, computed);
                                    }
                                }
                            }
                            request_response::Message::Response { request_id, response } => {
                                if ibd_inflight != Some((peer, request_id)) {
                                    debug!(peer = %peer, "Ignoring stale / non-IBD bead-sync response");
                                } else {
                                    ibd_inflight = None;
                                    match response {
                                        BeadResponse::Tips(tips) => {
                                            let (already_synced, peer_tips) = {
                                                let braid_lock = braid.read().await;
                                                let synced = !tips.0.is_empty()
                                                    && tips.0.iter().all(|t| braid_lock.bead_index_mapping.contains_key(t));
                                                (synced, tips.0)
                                            };
                                            sync_event = Some(SyncEvent::TipsReceived { peer, peer_tips, already_synced });
                                        }
                                        BeadResponse::GetBeadsAfter(bead_hashes) => {
                                            sync_event = Some(SyncEvent::HashPageReceived { peer, hashes: bead_hashes.0 });
                                        }
                                        BeadResponse::Beads(beads) | BeadResponse::GetAllBeads(beads) => {
                                            sync_event = Some(SyncEvent::BeadsReceived { peer, beads: beads.0 });
                                        }
                                        BeadResponse::Genesis(genesis) => {
                                            // Genesis recovery is adapter-local (see sync module docs).
                                            let status = { braid.read().await.check_genesis_beads(&genesis.0) };
                                            match status {
                                                braid::GenesisCheckStatus::GenesisBeadsValid => {
                                                    info!("Genesis beads valid");
                                                }
                                                braid::GenesisCheckStatus::MissingGenesisBead => {
                                                    warn!(peer = %peer, "Missing genesis bead; requesting it");
                                                    let req_id = swarm.behaviour_mut().request_beads(peer, &genesis.0);
                                                    ibd_inflight = Some((peer, req_id));
                                                }
                                                braid::GenesisCheckStatus::GenesisBeadsCountMismatch => {
                                                    warn!(received = %genesis.0.len(), peer = %peer, "Genesis bead count mismatch");
                                                }
                                            }
                                        }
                                        BeadResponse::Error(error) => match error {
                                            BeadSyncError::GenesisMismatch => {
                                                warn!(peer = %peer, "Genesis mismatch; requesting genesis");
                                                let req_id = swarm.behaviour_mut().request_genesis(peer);
                                                ibd_inflight = Some((peer, req_id));
                                            }
                                            BeadSyncError::BeadHashNotFound => {
                                                warn!(peer = %peer, "Peer reported a requested bead hash not found");
                                            }
                                        },
                                    }
                                }
                            }
                        }
                    }
                    SwarmEvent::Behaviour(BraidPoolBehaviourEvent::BeadSync(
                        request_response::Event::OutboundFailure { peer, request_id, error, .. },
                    )) => {
                        if ibd_inflight == Some((peer, request_id)) {
                            ibd_inflight = None;
                            warn!(peer = %peer, ?error, "IBD outbound request failed; switching sync peer");
                            sync_event = Some(SyncEvent::RequestFailed { peer });
                        } else {
                            debug!(peer = %peer, ?error, "Non-IBD outbound failure ignored");
                        }
                    }
                     other_event=>{
                             debug!(event = ?other_event, "Other swarm event");
                     }
                 }

             }
             Some(swarm_command) = swarm_command_receiver.recv()=>{
                 match swarm_command{
                     SwarmCommand::PropagateValidBead {
                         bead_bytes,
                     } => {
                         swarm
                             .behaviour_mut()
                             .bead_announce
                             .publish(current_broadcast_topic.clone(), bead_bytes);
                        info!(topic = ?current_broadcast_topic, "Published bead to floodsub topic");
                     },
                     SwarmCommand::InitiateIBD => {
                        // Select the best sync peer
                        let exclude = sync_engine.exhausted_peers();
                        let selected = {
                            let peer_manager = peer_manager_arc.read().await;
                            peer_manager.select_sync_peer(&exclude)
                        };
                        sync_event = Some(match selected {
                            Some(peer) => {
                                info!(peer = %peer, "Initiating IBD with selected sync peer");
                                SyncEvent::Start { peer }
                            }
                            None => {
                                warn!("No eligible sync peer available; scheduling IBD retry");
                                SyncEvent::NoPeerAvailable
                            }
                        });
                     }
                 }
             }




            }

            // A swarm/command arm queued an event above.
            if let Some(event) = sync_event.take() {
                let event_peer = event.peer();
                for action in sync_engine.on_event(event) {
                    match action {
                        SyncAction::SendRequest { peer, request } => {
                            let req_id =
                                swarm.behaviour_mut().bead_sync.send_request(&peer, request);
                            ibd_inflight = Some((peer, req_id));
                        }
                        SyncAction::RequestHashPage { peer } => {
                            // GetBeadsAfter our *current* tips, read after any
                            // ApplyBeads above so we never re-request the page just
                            // applied.
                            let mut local_tips: Vec<BeadHash> = {
                                let braid_data = braid.read().await;
                                braid_data
                                    .tips
                                    .iter()
                                    .filter_map(|idx| {
                                        braid_data
                                            .beads
                                            .get(*idx)
                                            .map(|b| b.block_header.block_hash())
                                    })
                                    .collect()
                            };
                            local_tips.sort();
                            let req_id = swarm.behaviour_mut().bead_sync.send_request(
                                &peer,
                                BeadRequest::GetBeadsAfter(BeadHashes(local_tips)),
                            );
                            ibd_inflight = Some((peer, req_id));
                        }
                        SyncAction::ApplyBeads { beads } => {
                            let outcome = {
                                let mut braid_data = braid.write().await;
                                ingest_beads(&mut braid_data, &beads)
                            };
                            let (added, invalid) = (outcome.added, outcome.invalid);
                            if let Some(cmd) = outcome.into_db_command() {
                                match db_tx.send(cmd).await {
                                    Ok(_) => info!(
                                        bead_count = added,
                                        "Batch insert queued for IBD beads"
                                    ),
                                    Err(error) => {
                                        error!(err = ?error.0, "Failed to queue IBD beads for persistence")
                                    }
                                }
                            }
                            if let Some(peer) = event_peer {
                                if added > 0 || invalid > 0 {
                                    let mut peer_manager = peer_manager_arc.write().await;
                                    for _ in 0..invalid {
                                        peer_manager.penalize_for_invalid_bead(&peer);
                                    }
                                    if added > 0 {
                                        peer_manager.update_score(&peer, added as f64);
                                    }
                                }
                            }
                        }
                        SyncAction::DisconnectPeer { peer } => {
                            ibd_inflight = None;
                            if swarm.disconnect_peer_id(peer).is_err() {
                                warn!(peer = %peer, "disconnect_peer_id returned Err; peer may already be disconnected");
                            }
                        }
                        SyncAction::ScheduleRetry { after } => {
                            let sender = swarm_command_sender.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(after).await;
                                if let Err(error) = sender.send(SwarmCommand::InitiateIBD).await {
                                    error!(error = ?error, "Failed to reinitiate IBD after retry delay");
                                }
                            });
                        }
                        SyncAction::MarkComplete => {
                            ibd_spinlock.store(false, Ordering::SeqCst);
                        }
                    }
                }
            }
        }
    });

    //graceful shutdown via `Cancellation token`
    let shutdown_signal = tokio::signal::ctrl_c().await;
    match shutdown_signal {
        Ok(_) => {
            info!(component = "database", "Closing connection pool");
            //Closing all the existing connections to pool and committing from .db-wal to .db
            db_connection_pool.close().await;
            info!(component = "database", "Connections closed");
            info!(component = "swarm", "Shutting down network swarm");
            swarm_handle.abort();
            tokio::time::sleep(Duration::from_millis(1)).await;
            #[allow(unused)]
            let shutdown_sub_tasks = match main_shutdown_tx
                .send(tokio::signal::unix::SignalKind::interrupt())
                .await
            {
                Ok(_) => {
                    info!(
                        component = "shutdown",
                        "Sub-tasks interrupted - waiting for graceful shutdown"
                    );
                    main_task_token.cancel();
                }
                Err(error) => {
                    error!(error = ?error, "Failed to send interrupt signal to sub-tasks");
                }
            };
        }
        Err(error) => {
            error!(
                error = ?error,
                component = "shutdown",
                "Shutdown signal error"
            );
        }
    }

    Ok(())
}
