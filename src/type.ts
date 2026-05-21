export interface RiskFinding {
  level: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  message: string;
}
