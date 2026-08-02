import { createContext } from 'react'
import type { User } from '../types'

export interface AuthValue {
  user: User | null
  login: (email: string, password: string) => Promise<void>
  logout: () => void
}

export const AuthContext = createContext<AuthValue | null>(null)
