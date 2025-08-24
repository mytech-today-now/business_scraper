-- Migration: Add AI Analytics and Insights Tables
-- Version: 003
-- Description: Creates tables for AI analytics data and insights storage

-- AI Analytics Table
-- Stores AI analysis results and data processing information
CREATE TABLE IF NOT EXISTS ai_analytics (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  campaign_id UUID REFERENCES campaigns(id) ON DELETE CASCADE,
  analysis_type VARCHAR(100) NOT NULL,
  data JSONB NOT NULL DEFAULT '{}',
  insights JSONB NOT NULL DEFAULT '{}',
  confidence_score DECIMAL(5,4) DEFAULT 0.0 CHECK (confidence_score >= 0.0 AND confidence_score <= 1.0),
  processing_time_ms INTEGER DEFAULT 0,
  model_version VARCHAR(50) DEFAULT 'v1.0',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- AI Insights Table  
-- Stores AI-generated insights and recommendations
CREATE TABLE IF NOT EXISTS ai_insights (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title VARCHAR(255) NOT NULL,
  summary TEXT NOT NULL,
  recommendations JSONB DEFAULT '[]',
  data_sources JSONB DEFAULT '[]',
  confidence_level VARCHAR(20) DEFAULT 'medium' CHECK (confidence_level IN ('low', 'medium', 'high')),
  impact_score DECIMAL(5,4) DEFAULT 0.0 CHECK (impact_score >= 0.0 AND impact_score <= 1.0),
  category VARCHAR(100) DEFAULT 'general',
  tags JSONB DEFAULT '[]',
  expires_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- AI Jobs Table
-- Tracks background AI processing jobs
CREATE TABLE IF NOT EXISTS ai_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_type VARCHAR(100) NOT NULL,
  status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
  campaign_id UUID REFERENCES campaigns(id) ON DELETE CASCADE,
  input_data JSONB DEFAULT '{}',
  output_data JSONB DEFAULT '{}',
  error_message TEXT,
  progress_percentage DECIMAL(5,2) DEFAULT 0.0 CHECK (progress_percentage >= 0.0 AND progress_percentage <= 100.0),
  started_at TIMESTAMP WITH TIME ZONE,
  completed_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance optimization
CREATE INDEX IF NOT EXISTS idx_ai_analytics_campaign_id ON ai_analytics(campaign_id);
CREATE INDEX IF NOT EXISTS idx_ai_analytics_analysis_type ON ai_analytics(analysis_type);
CREATE INDEX IF NOT EXISTS idx_ai_analytics_created_at ON ai_analytics(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ai_insights_category ON ai_insights(category);
CREATE INDEX IF NOT EXISTS idx_ai_insights_confidence_level ON ai_insights(confidence_level);
CREATE INDEX IF NOT EXISTS idx_ai_insights_created_at ON ai_insights(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_insights_expires_at ON ai_insights(expires_at);

CREATE INDEX IF NOT EXISTS idx_ai_jobs_status ON ai_jobs(status);
CREATE INDEX IF NOT EXISTS idx_ai_jobs_job_type ON ai_jobs(job_type);
CREATE INDEX IF NOT EXISTS idx_ai_jobs_campaign_id ON ai_jobs(campaign_id);
CREATE INDEX IF NOT EXISTS idx_ai_jobs_created_at ON ai_jobs(created_at DESC);

-- Triggers for updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_ai_analytics_updated_at BEFORE UPDATE ON ai_analytics 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_ai_insights_updated_at BEFORE UPDATE ON ai_insights 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_ai_jobs_updated_at BEFORE UPDATE ON ai_jobs 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert migration record
INSERT INTO schema_migrations (version, description, applied_at) 
VALUES ('003', 'Add AI Analytics and Insights Tables', CURRENT_TIMESTAMP)
ON CONFLICT (version) DO NOTHING;

-- Comments for documentation
COMMENT ON TABLE ai_analytics IS 'Stores AI analysis results and processing data for campaigns';
COMMENT ON TABLE ai_insights IS 'Stores AI-generated insights and recommendations for business intelligence';
COMMENT ON TABLE ai_jobs IS 'Tracks background AI processing jobs and their status';

COMMENT ON COLUMN ai_analytics.confidence_score IS 'AI confidence score between 0.0 and 1.0';
COMMENT ON COLUMN ai_analytics.processing_time_ms IS 'Time taken to process the analysis in milliseconds';
COMMENT ON COLUMN ai_insights.impact_score IS 'Potential business impact score between 0.0 and 1.0';
COMMENT ON COLUMN ai_insights.expires_at IS 'When this insight expires and should no longer be shown';
COMMENT ON COLUMN ai_jobs.progress_percentage IS 'Job completion percentage between 0.0 and 100.0';
