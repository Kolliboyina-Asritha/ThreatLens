/**
 * Standard Success Response
 * @param {object} res - Express response
 * @param {number} statusCode
 * @param {string} message
 * @param {any} data
 * @param {object} meta - Optional pagination/metadata
 */
export const successResponse = (res, statusCode = 200, message = 'Success', data = null, meta = undefined) => {
  const payload = {
    success: true,
    message,
    ...(data !== null && { data }),
    ...(meta !== undefined && { meta })
  };
  return res.status(statusCode).json(payload);
};

/**
 * Standard Error Response
 * @param {object} res - Express response
 * @param {number} statusCode
 * @param {string} message
 * @param {any} errors
 */
export const errorResponse = (res, statusCode = 500, message = 'An error occurred', errors = undefined) => {
  const payload = {
    success: false,
    message,
    ...(errors !== undefined && { errors })
  };
  return res.status(statusCode).json(payload);
};
