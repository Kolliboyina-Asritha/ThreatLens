export const requestLogger = (req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const { method, originalUrl, ip } = req;
    const { statusCode } = res;
    
    // Log basic metadata without logging request body (which could contain passwords)
    console.log(`[HTTP] ${method} ${originalUrl} ${statusCode} - ${duration}ms (${ip})`);
  });

  next();
};
