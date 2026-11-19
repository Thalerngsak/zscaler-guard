// Made-up samples, built at run time so no file or command of this repository carries a literal
// value a DLP proxy (or a secret scanner) would match. Check digits are computed, not written.

import { ibanOk, luhnOk, thaiIdOk } from '../hooks/detect'

export const j = (...p: string[]) => p.join('')
export const TAG = j('RE', 'DACTED')

// 12 digits plus the mod-11 check digit
export function thaiId(body12: string): string {
  for (let c = 0; c < 10; c++) if (thaiIdOk(body12 + c)) return body12 + c
  throw new Error('no check digit')
}

// a body plus the Luhn check digit
export function luhn(body: string): string {
  for (let c = 0; c < 10; c++) if (luhnOk(body + c)) return body + c
  throw new Error('no check digit')
}

// country + check digits + BBAN, check digits computed by ISO 13616
export function iban(country: string, bban: string): string {
  for (let k = 2; k < 99; k++) {
    const v = country + String(k).padStart(2, '0') + bban
    if (ibanOk(v)) return v
  }
  throw new Error('no check digits')
}

export const group4 = (d: string) => d.replace(/(\d{4})(?=\d)/g, '$1 ')

export const ID = thaiId(j('1', '1020', '30405', '06'))
export const ID_DASHED = `${ID[0]}-${ID.slice(1, 5)}-${ID.slice(5, 10)}-${ID.slice(10, 12)}-${ID[12]}`
export const CARD = group4(luhn(j('4', '000', '1234', '5678', '901')))
export const IBAN = iban('GB', j('ABCD', '1020', '3040', '5060', '70'))
export const PEM = (body = 'Q'.repeat(64)) => j('-----BEGIN RSA ', 'PRIVATE KEY-----\n', body, '\n-----END RSA ', 'PRIVATE KEY-----')
export const GH_TOKEN = j('gh', 'p_', 'a1B2'.repeat(9))
export const AWS_ID = j('AK', 'IA', 'ABCDEFGH', '12345678')
export const DB_URL = j('postgres://', 'app:', 'n0t', 'Real', 'Pw', '@db.internal:5432/loans')
