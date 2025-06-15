import axios from 'axios';

export const getCurrencySymbol = (curr: string) => {
  switch (curr) {
    case 'EUR':
      return '€';
    case 'GBP':
      return '£';
    case 'JPY':
      return '¥';
    default:
      return '$';
  }
};

export const formatPrice = (value: number): string => {
  if (!value) return '--';
  return new Intl.NumberFormat('en-US', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(value);
};

export const formatLargeNumber = (value: number): string => {
  if (!value) return '--';
  if (value >= 1e12) return `${(value / 1e12).toFixed(2)}T`;
  if (value >= 1e9) return `${(value / 1e9).toFixed(2)}B`;
  if (value >= 1e6) return `${(value / 1e6).toFixed(2)}M`;
  return new Intl.NumberFormat('en-US').format(value);
};

export const shortenAddress = (value: string): string => {
  return value.slice(0, 7) + '....' + value.slice(-7);
};

// via esplora
export const getLatestTransactions = async (): Promise<any> => {
  try {
    const response = await axios.get('http://localhost:3002/mempool/recent');
    console.log(response.data);
    return response.data;
  } catch (error) {
    console.error('Error fetching transactions:', error);
    throw error;
  }
};

// via esplora
export const getTxInfo = async (txid: string): Promise<any> => {
  try {
    const response = await axios.get(`http://localhost:3002/tx/${txid}`);
    console.log(response.data);
    return response.data;
  } catch (error) {
    console.error('Error fetching transactions:', error);
    throw error;
  }
};

// via mempool api
export const latestRBFTransactions = async (): Promise<any> => {
  try {
    const response = await axios.get(
      `http://localhost:8999/api/v1/replacements`
    );
    console.log(response.data);
    return response.data;
  } catch (error) {
    console.error('Error fetching RBF Transactions:', error);
    throw error;
  }
};
