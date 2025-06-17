#![allow(unused)]
use crate::bead::Bead;
use crate::committed_metadata::CommittedMetadata;
use crate::committed_metadata::TimeVec;
use crate::uncommitted_metadata::UnCommittedMetadata;
use bitcoin::absolute::Time;
use bitcoin::ecdsa::Signature;
use bitcoin::p2p::ServiceFlags;
use bitcoin::{
    Address, BlockHash, BlockHeader, BlockTime, BlockVersion, CompactTarget, EcdsaSighashType,
    TxMerkleNode,
};
use jsonrpsee::core::middleware::{Batch, Notification, Request, RpcServiceT};
use jsonrpsee::core::{async_trait, SubscriptionResult};
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::PendingSubscriptionSink;
use jsonrpsee::types::{ErrorObject, ErrorObjectOwned};
use jsonrpsee::ws_client::WsClientBuilder;
use jsonrpsee::{ConnectionId, Extensions};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use tokio::time;
//parsing the inital rpc command line all
pub fn parse_arguments(rpc_arguments: String) {}

//handling the request arising either from command line cli or from the external users
pub async fn handle_request() {}

//server side trait to be implemented for the handler
//that is the JSON-RPC handle to initiate the RPC context
//supporting both http and websockets
#[rpc(server)]
pub trait Rpc {
    //RPC methods supported by braid-API
    #[method(name = "test_rpc_bead")]
    async fn test_rpc_bead(&self, bead_hash: String) -> Result<Bead, ErrorObjectOwned>;
}
#[async_trait]
impl RpcServer for RpcServerImpl {
    async fn test_rpc_bead(&self, bead_hash: String) -> Result<Bead, ErrorObjectOwned> {
        let test_sock_add = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8888);
        // let _address = P2P_Address::new(&test_sock_add.clone(), ServiceFlags::NONE);
        let public_key = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<bitcoin::PublicKey>()
            .unwrap();
        let socket = bitcoin::p2p::address::AddrV2::Ipv4(Ipv4Addr::new(127, 0, 0, 1));
        let time_hash_set = TimeVec(Vec::new());
        let parent_hash_set: HashSet<BlockHash> = HashSet::new();
        let weak_target = CompactTarget::from_consensus(32);
        let min_target = CompactTarget::from_consensus(1);
        let time_val = Time::from_consensus(1653195600).unwrap();
        let test_committed_metadata: CommittedMetadata = CommittedMetadata {
            comm_pub_key: public_key,
            min_target: min_target,
            miner_ip: "".to_string(),
            transactions: vec![],
            parents: parent_hash_set,
            parent_bead_timestamps: time_hash_set,
            payout_address: String::from(""),
            start_timestamp: time_val,
            weak_target: weak_target,
        };
        let extra_nonce = 42;
        let hex = "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45";
        let sig = Signature {
            signature: secp256k1::ecdsa::Signature::from_str(hex).unwrap(),
            sighash_type: EcdsaSighashType::All,
        };
        let test_uncommitted_metadata = UnCommittedMetadata {
            broadcast_timestamp: time_val,
            extra_nonce: extra_nonce,
            signature: sig,
        };
        let test_bytes: [u8; 32] = [0u8; 32];
        let test_block_header = BlockHeader {
            version: BlockVersion::TWO,
            prev_blockhash: BlockHash::from_byte_array(test_bytes),
            bits: CompactTarget::from_consensus(32),
            nonce: 1,
            time: BlockTime::from_u32(8328429),
            merkle_root: TxMerkleNode::from_byte_array(test_bytes),
        };
        let test_bead = Bead {
            block_header: test_block_header,
            committed_metadata: test_committed_metadata,
            uncommitted_metadata: test_uncommitted_metadata,
        };
        Ok(test_bead)
    }
}
//server building
pub struct RpcServerImpl;

//running a server in seperate spawn event
pub async fn run_rpc_server() -> Result<SocketAddr, ()> {
    //Initializing the middleware
    let rpc_middleware = jsonrpsee::server::middleware::rpc::RpcServiceBuilder::new();
    //building the context/server supporting the http transport and ws
    let server = jsonrpsee::server::Server::builder()
        .set_rpc_middleware(rpc_middleware)
        .build("127.0.0.1:0")
        .await
        .unwrap();
    //listening address for incoming requests/connection
    let addr = server.local_addr().unwrap();
    //context for the served server
    let handle = server.start(RpcServerImpl.into_rpc());
    println!("{:?}", addr);
    //handling the stopping of the server
    handle.stopped().await;
    Ok(addr)
}
