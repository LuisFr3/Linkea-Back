import crypto from "crypto"

/**
 * Genera un token seguro para reset de contraseña
 * @returns Token hexadecimal de 32 bytes
 */
export const generateResetToken = (): string => {
  return crypto.randomBytes(32).toString("hex")
}

/**
 * Genera la fecha de expiración del token (1 hora desde ahora)
 * @returns Fecha de expiración
 */
export const generateTokenExpiration = (): Date => {
  const expiration = new Date()
  expiration.setHours(expiration.getHours() + 1) // Token válido por 1 hora
  return expiration
}

/**
 * Verifica si un token ha expirado
 * @param expirationDate Fecha de expiración del token
 * @returns true si el token ha expirado, false si aún es válido
 */
export const isTokenExpired = (expirationDate: Date): boolean => {
  return new Date() > expirationDate
}
