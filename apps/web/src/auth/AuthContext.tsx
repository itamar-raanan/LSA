import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { api, SESSION_INVALID_EVENT } from '../api/client'
import type { User } from '../types'
import { AuthContext, type AuthValue } from './context'

function loadUser(): User | null {
  if (!localStorage.getItem('lsa_session')) {
    localStorage.removeItem('lsa_user')
    return null
  }
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
  useEffect(() => {
    const invalidate = () => setUser(null)
    window.addEventListener(SESSION_INVALID_EVENT, invalidate)
    return () => window.removeEventListener(SESSION_INVALID_EVENT, invalidate)
  }, [])
  const value = useMemo<AuthValue>(
    () => ({
      user,
      async login(email, password) {
        const response = await api.login(email, password)
        localStorage.setItem('lsa_session', response.access_token)
        localStorage.setItem('lsa_user', JSON.stringify(response.user))
        setUser(response.user)
      },
      async radiusLogin(username, password) {
        const response = await api.radiusLogin(username, password)
        localStorage.setItem('lsa_session', response.access_token)
        localStorage.setItem('lsa_user', JSON.stringify(response.user))
        setUser(response.user)
      },
      acceptSession(token, acceptedUser) {
        localStorage.setItem('lsa_session', token)
        localStorage.setItem('lsa_user', JSON.stringify(acceptedUser))
        setUser(acceptedUser)
      },
      logout() {
        void api.logout().catch(() => undefined)
        localStorage.removeItem('lsa_session')
        localStorage.removeItem('lsa_user')
        setUser(null)
      },
    }),
    [user],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
