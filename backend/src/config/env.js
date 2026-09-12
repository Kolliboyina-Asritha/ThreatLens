import dotenv from 'dotenv';
dotenv.config();

export const env = {
  PORT: process.env.PORT || 5000,
  MONGODB_URI: process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/threatlens?directConnection=true',
  JWT_ACCESS_SECRET: process.env.JWT_ACCESS_SECRET || 'threatlens_default_access_secret_for_dev_only_32_chars',
  JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET || 'threatlens_default_refresh_secret_for_dev_only_32_chars',
  CLIENT_URL: process.env.CLIENT_URL || 'http://localhost:5173',
  NODE_ENV: process.env.NODE_ENV || 'development',

  // Phase 2: ML Service Integration
  ML_SERVICE_URL: process.env.ML_SERVICE_URL || 'http://localhost:8000',

  // Phase 2: Threat Intelligence (VirusTotal)
  VIRUSTOTAL_API_KEY: process.env.VIRUSTOTAL_API_KEY || '',
  VIRUSTOTAL_BASE_URL: process.env.VIRUSTOTAL_BASE_URL || 'https://www.virustotal.com/api/v3',

  // Phase 2: Generative AI / LLM
  LLM_API_KEY: process.env.LLM_API_KEY || '',
  LLM_MODEL: process.env.LLM_MODEL || 'gemini-1.5-flash',
  LLM_BASE_URL: process.env.LLM_BASE_URL || 'https://generativelanguage.googleapis.com/v1beta'
};

if (!process.env.JWT_ACCESS_SECRET && env.NODE_ENV === 'production') {
  console.warn('WARNING: JWT_ACCESS_SECRET is not set in production!');
}

if (!process.env.JWT_REFRESH_SECRET && env.NODE_ENV === 'production') {
  console.warn('WARNING: JWT_REFRESH_SECRET is not set in production!');
}
