export type SourceMode = 'Message' | 'Link' | 'Screenshot';

export interface UrlAnalysis {
  success?: boolean;
  url?: string;
  domain?: string;
  score?: number;
  level?: string;
  signals?: string[];
  reasons?: string[];
}

export interface AiAnalysisResult {
  likely_scam?: boolean;
  scam_type?: string;
  confidence?: number | null;
  confidence_source?: string;
  manipulation_tactics?: string[];
  explanation?: string;
  recommended_action?: string;
}

export interface AiAnalysis {
  available?: boolean;
  status?: string;
  model?: string;
  error?: string;
  result?: AiAnalysisResult;
}

export interface ScamAnalysis {
  success: boolean;
  message?: string;
  final_score?: number;
  final_level?: string;
  final_category?: string;
  rule_score?: number;
  rule_level?: string;
  rule_category?: string;
  signals?: string[];
  reasons?: string[];
  actions?: string[];
  url_analysis?: UrlAnalysis | null;
  ai_analysis?: AiAnalysis;
  fusion_evidence?: string[];
  source_mode?: SourceMode;
}

export interface AnalyzeResponse {
  success: boolean;
  result: ScamAnalysis;
  analyzed_text?: string;
  source_mode?: SourceMode;
  ocr_text?: string;
  filename?: string;
}

export interface ApiHealth {
  status: string;
  service?: string;
  version?: string;
  runtime?: string;
  model?: string;
  storage?: string;
}
