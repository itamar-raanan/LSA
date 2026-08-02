import { createContext, useContext, useMemo, useState, type ReactNode } from 'react'
import { api } from '../api/client'
import type { User } from '../types'

interface AuthValue {
  user: User | null
  login: (email: string, password: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthValue | null>(null)

function loadUser(): User | null {
  const raw = localStorage.getItem('lsa_user')
  if (!raw) return null
  try {
    return JSON.parse(raw) as User
  } catch {
    localStorage.removeItem('lsa_user')
    return null
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(loadUser)
  const value = useMemo<AuthValue>(
    () => ({
      user,
      async login(email, password) {
        const response = await api.login(email, password)
        localStorage.setItem('lsa_session', response.access_token)
        localStorage.setItem('lsa_user', JSON.stringify(response.user))
        setUser(response.user)
      },
      logout() {
        localStorage.removeItem('lsa_session')
        localStorage.removeItem('lsa_user')
        setUser(null)
      },
    }),
    [user],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const value = useContext(AuthContext)
  if (!value) throw new Error('useAuth must be used inside AuthProvider')
  return value
}

