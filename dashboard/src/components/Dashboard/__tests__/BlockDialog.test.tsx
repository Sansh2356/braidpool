import '@testing-library/jest-dom';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import BlockInfoDialog from '../BlockDialog';
import * as utils from '../Utils';

Object.assign(navigator, {
  clipboard: {
    writeText: jest.fn(),
  },
});

const mockBlockInfo = {
  id: '0000000000000000000bba9f...',
  height: 123456,
  timestamp: 1717653123,
  version: 1,
  bits: '1a2b3c',
  nonce: 234567,
  difficulty: 1234567890,
  merkle_root: 'abcd1234efgh5678',
  tx_count: 2000,
  size: 123456,
  weight: 400000,
  previousblockhash: '0000000000000000000aabb...',
  extras: {
    reward: 625000000,
    totalFees: 5000000,
    pool: { name: 'F2Pool' },
    matchRate: 95.7,
    medianFee: 15,
  },
};

jest.spyOn(utils, 'getBlockInfo');

describe('BlockInfoDialog', () => {
  const onClose = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('shows loading indicator initially', async () => {
    (utils.getBlockInfo as jest.Mock).mockReturnValue(new Promise(() => {}));

    render(<BlockInfoDialog hash="testhash" onClose={onClose} />);
    expect(screen.getByText(/loading block data/i)).toBeInTheDocument();
  });

  it('displays error message on fetch failure', async () => {
    (utils.getBlockInfo as jest.Mock).mockRejectedValue(
      new Error('Fetch error')
    );

    render(<BlockInfoDialog hash="badHash" onClose={onClose} />);
    await waitFor(() =>
      expect(
        screen.getByText(/failed to load block details/i)
      ).toBeInTheDocument()
    );
  });

  it('renders block details on success', async () => {
    (utils.getBlockInfo as jest.Mock).mockResolvedValue(mockBlockInfo);

    render(<BlockInfoDialog hash="goodHash" onClose={onClose} />);

    await waitFor(() => {
      expect(screen.getByText(/Block ID \(Hash\)/)).toBeInTheDocument();
    });

    expect(screen.getByText(mockBlockInfo.id)).toBeInTheDocument();
    expect(screen.getByText(mockBlockInfo.height)).toBeInTheDocument();
    expect(screen.getByText(/F2Pool/)).toBeInTheDocument();
  });

  it('copies block hash to clipboard', async () => {
    (utils.getBlockInfo as jest.Mock).mockResolvedValue(mockBlockInfo);

    render(<BlockInfoDialog hash="hashToCopy" onClose={onClose} />);

    await waitFor(() =>
      expect(screen.getByText(mockBlockInfo.id)).toBeInTheDocument()
    );

    fireEvent.click(screen.getByLabelText(/copy block hash/i));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
      mockBlockInfo.id
    );

    expect(await screen.findByText(/copied!/i)).toBeInTheDocument();
  });

  it('calls onClose when background is clicked', async () => {
    (utils.getBlockInfo as jest.Mock).mockResolvedValue(mockBlockInfo);

    render(<BlockInfoDialog hash="hashToClose" onClose={onClose} />);

    await waitFor(() =>
      expect(screen.getByText(mockBlockInfo.id)).toBeInTheDocument()
    );

    fireEvent.click(screen.getByText('', { selector: '.fixed.inset-0' }));
    expect(onClose).toHaveBeenCalled();
  });
});
