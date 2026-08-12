import { useState, useEffect, useRef } from 'react'
import { Send, Plus, Copy, Check, User, Settings, Shield, Zap, MessageSquare, LogOut, ChevronLeft, ChevronRight } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Toaster, toast } from 'sonner'

// Types
interface Message {
  id: string
  role: 'user' | 'assistant'
  content: string
  timestamp: Date
}

interface Conversation {
  id: string
  title: string
  messages: Message[]
  updatedAt: Date
}

type ModelOption = {
  id: string
  label: string
  provider: string
}

interface PendingAccessRequest {
  requestId: string
  status: string
  actionType?: string
  description?: string
  lastPolledAt?: string
  action?: {
    type: string
    target?: Record<string, string>
    parameters?: Record<string, unknown>
    description?: string
  }
}

const PENDING_STORAGE_KEY = 'sdap_pending_access_requests'
const ACCESS_REQUEST_POLL_MS = 15000

const TERMINAL_ACCESS_REQUEST_STATUSES = new Set([
  'denied', 'rejected', 'cancelled', 'canceled', 'expired',
  'approved_executed', 'approved_execution_failed', 'closed', 'completed',
])

function isTerminalAccessRequestStatus(status: string) {
  return TERMINAL_ACCESS_REQUEST_STATUSES.has(String(status || '').toLowerCase())
}

function accessRequestStatusLabel(status: string) {
  if (status === 'approved_pending_grant') return 'approved, executing…'
  return String(status || 'unknown').replace(/_/g, ' ')
}

function toastForAccessRequestStatus(requestId: string, status: string, execution?: { ok?: boolean; oktaOperation?: string; error?: string }) {
  const short = `${requestId.slice(0, 8)}…`
  if (execution?.ok && execution.oktaOperation) {
    toast.success(`Action completed (${short}): ${execution.oktaOperation}`)
    return
  }
  if (execution && execution.ok === false) {
    toast.error(`Action failed (${short}): ${execution.error || 'execution error'}`)
    return
  }
  if (['approved_executed', 'completed', 'closed'].includes(status)) {
    toast.success(`Access request ${short} approved and executed`)
  } else if (['denied', 'rejected'].includes(status)) {
    toast.error(`Access request ${short} was denied`)
  } else if (['cancelled', 'canceled'].includes(status)) {
    toast.info(`Access request ${short} was cancelled`)
  } else if (status === 'approved_execution_failed') {
    toast.error(`Access request ${short} approved but execution failed`)
  } else if (status === 'expired') {
    toast.info(`Access request ${short} expired`)
  } else {
    toast.info(`Access request ${short}: ${accessRequestStatusLabel(status)}`)
  }
}



const SUGGESTED_PROMPTS = [
  "Show me users with recent failed sign-ins",
  "How do I force MFA reset for a user?",
  "What are current sign-on policy rules?",
  "List all admin roles and who has them",
  "Help troubleshoot why a user can't access an app",
  "Draft a policy for privileged access reviews",
]

const QUICK_ACTIONS = [
  { id: 'list-users', label: 'List Recent Users', desc: 'Fetch last 20 users from Okta', icon: User, danger: false },
  { id: 'failed-logins', label: 'Recent Failed Logins', desc: 'Query system logs for auth failures', icon: Shield, danger: false },
  { id: 'suspend-user', label: 'Request User Suspension', desc: 'Trigger approval workflow', icon: Zap, danger: true },
  { id: 'reset-mfa', label: 'Reset User MFA Factors', desc: 'Requires approval in Okta', icon: Settings, danger: true },
]

function App() {
  // UI State
  const [currentView, setCurrentView] = useState<'chat' | 'actions' | 'users' | 'settings'>('chat')
  const [sidebarOpen, setSidebarOpen] = useState(() =>
    typeof window !== 'undefined' ? window.innerWidth > 768 : true
  )

  // On mobile the sidebar is an overlay drawer — collapse it after a selection
  const closeSidebarOnMobile = () => {
    if (typeof window !== 'undefined' && window.innerWidth <= 768) {
      setSidebarOpen(false)
    }
  }

  // Chat State
  const [conversations, setConversations] = useState<Conversation[]>([])
  const [currentConvId, setCurrentConvId] = useState<string | null>(null)
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [selectedModel, setSelectedModel] = useState<string>('')
  const [availableModels, setAvailableModels] = useState<ModelOption[]>([])
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [pendingAccessRequests, setPendingAccessRequests] = useState<PendingAccessRequest[]>([])

  const pendingAccessRequestsRef = useRef<PendingAccessRequest[]>([])
  const notifiedTerminalRef = useRef<Set<string>>(new Set())

  // Auth state for splash page (SP-initiated flow)
  type AuthStatus = 'loading' | 'authenticated' | 'unauthenticated'
  const [authStatus, setAuthStatus] = useState<AuthStatus>('loading')
  const [needsReauth, setNeedsReauth] = useState(false)

  // Auth state - supports both DEMO_AUTH_BYPASS and real OIDC
  const [currentUser, setCurrentUser] = useState({
    name: '',
    email: '',
    role: '',
  })
  const [, setAuthLoading] = useState(true)

  const API_BASE = (import.meta.env.VITE_API_BASE || '').replace(/\/$/, '')

  // Load available models from backend (only show ones we have keys for)
  // and check auth status
  useEffect(() => {
    // Load models first
    fetch(`${API_BASE}/api/available-models`)
      .then(r => (r.ok ? r.json() : []))
      .then((models: ModelOption[]) => {
        setAvailableModels(models)

        if (models.length > 0) {
          setSelectedModel(prev => {
            if (prev && models.some(m => m.id === prev)) return prev

            // Prefer Grok if available
            const grokModel = models.find(m => m.provider === 'grok')
            if (grokModel) return grokModel.id

            return models[0].id
          })
        }
      })
      .catch(() => {
        setAvailableModels([])
      })

    // Check auth status
    fetch(`${API_BASE}/api/auth/me`, { credentials: 'include' })
      .then(r => {
        if (!r.ok) {
          setAuthStatus('unauthenticated')
          return null
        }
        return r.json()
      })
      .then(data => {
        if (data?.user) {
          setCurrentUser({
            name: data.user.name || data.user.email,
            email: data.user.email,
            role: data.user.authMethod === 'oidc' ? 'Super Admin (OIDC)' : 'Admin',
          })
          setAuthStatus('authenticated')
          setNeedsReauth(Boolean(data.needsReauth))
          if (data.needsReauth) {
            toast.warning('Okta sign-in token expired — sign out and sign in again for agent tools (secrets, delegated API).')
          }
        } else {
          setAuthStatus('unauthenticated')
          setNeedsReauth(false)
        }
      })
      .catch(() => {
        setAuthStatus('unauthenticated')
      })
      .finally(() => setAuthLoading(false))
  }, [])

  // Re-check id_token freshness while signed in (cookie lasts 12h; id_token ~1h)
  useEffect(() => {
    if (authStatus !== 'authenticated') return
    const check = () => {
      fetch(`${API_BASE}/api/auth/me`, { credentials: 'include' })
        .then(r => (r.ok ? r.json() : null))
        .then(data => {
          if (!data?.user) return
          const stale = Boolean(data.needsReauth)
          setNeedsReauth(stale)
        })
        .catch(() => {})
    }
    const timer = window.setInterval(check, 5 * 60 * 1000)
    return () => window.clearInterval(timer)
  }, [authStatus, API_BASE])

  const messagesEndRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    pendingAccessRequestsRef.current = pendingAccessRequests
  }, [pendingAccessRequests])

  useEffect(() => {
    if (authStatus !== 'authenticated') return
    try {
      const raw = localStorage.getItem(PENDING_STORAGE_KEY)
      if (raw) {
        const parsed = JSON.parse(raw) as PendingAccessRequest[]
        setPendingAccessRequests(parsed.filter(p => p.requestId && !isTerminalAccessRequestStatus(p.status)))
      }
    } catch {
      /* ignore corrupt storage */
    }
  }, [authStatus])

  useEffect(() => {
    if (authStatus !== 'authenticated') return

    const pollAll = async () => {
      const active = pendingAccessRequestsRef.current.filter(p => !isTerminalAccessRequestStatus(p.status))
      if (active.length === 0) return

      for (const pending of active) {
        if (pending.action?.type) {
          try {
            await fetch(`${API_BASE}/api/agent/access-request/${encodeURIComponent(pending.requestId)}/context`, {
              method: 'POST',
              credentials: 'include',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                action: pending.action,
                description: pending.description,
              }),
            })
          } catch {
            /* context restore is best-effort */
          }
        }
      }

      const updates: { requestId: string; status: string; terminal: boolean; execution?: { ok?: boolean; oktaOperation?: string; error?: string } }[] = []
      for (const pending of active) {
        try {
          const res = await fetch(
            `${API_BASE}/api/agent/access-request/${encodeURIComponent(pending.requestId)}/status`,
            { credentials: 'include' }
          )
          if (!res.ok) continue
          const data = await res.json()
          updates.push({
            requestId: pending.requestId,
            status: data.status,
            terminal: Boolean(data.terminal ?? isTerminalAccessRequestStatus(data.status)),
            execution: data.execution,
          })
        } catch {
          /* ignore transient poll errors */
        }
      }

      if (updates.length === 0) return

      setPendingAccessRequests(prev => {
        let next = prev.map(p => {
          const u = updates.find(x => x.requestId === p.requestId)
          if (!u) return p
          return { ...p, status: u.status, lastPolledAt: new Date().toISOString() }
        })

        for (const u of updates) {
          if (u.terminal && !notifiedTerminalRef.current.has(u.requestId)) {
            notifiedTerminalRef.current.add(u.requestId)
            toastForAccessRequestStatus(u.requestId, u.status, u.execution)
          }
        }

        next = next.filter(p => !isTerminalAccessRequestStatus(p.status))
        localStorage.setItem(PENDING_STORAGE_KEY, JSON.stringify(next))
        return next
      })
    }

    pollAll()
    const timer = window.setInterval(pollAll, ACCESS_REQUEST_POLL_MS)
    return () => window.clearInterval(timer)
  }, [authStatus, API_BASE])

  // Load conversations from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('sdap_conversations')
    if (saved) {
      try {
        const parsed: Conversation[] = JSON.parse(saved).map((c: any) => ({
          ...c,
          updatedAt: new Date(c.updatedAt),
          messages: c.messages.map((m: any) => ({ ...m, timestamp: new Date(m.timestamp) }))
        }))
        setConversations(parsed)
        
        if (parsed.length > 0) {
          const latest = parsed[0]
          setCurrentConvId(latest.id)
          setMessages(latest.messages)
        }
      } catch (e) {
        console.error('Failed to load conversations', e)
      }
    } else {
      // Seed a welcome conversation
      const welcome: Conversation = {
        id: 'welcome-' + Date.now(),
        title: 'Welcome to Super Duper Admin Portal',
        messages: [
          {
            id: 'm1',
            role: 'assistant',
            content: "Hello! I'm your Okta admin assistant for **sledai.oktapreview.com**.\n\nI can help with user management, policies, troubleshooting, and safe execution of admin actions (all destructive actions go through approval workflows).\n\nWhat would you like to do today?",
            timestamp: new Date(),
          }
        ],
        updatedAt: new Date(),
      }
      setConversations([welcome])
      setCurrentConvId(welcome.id)
      setMessages(welcome.messages)
    }
  }, [])

  // Persist conversations
  useEffect(() => {
    if (conversations.length > 0) {
      localStorage.setItem('sdap_conversations', JSON.stringify(conversations))
    }
  }, [conversations])

  // Auto scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, isLoading])

  // Get current conversation (used for title updates etc.)
  // const currentConv = conversations.find(c => c.id === currentConvId)

  const createNewChat = () => {
    const newConv: Conversation = {
      id: 'conv-' + Date.now(),
      title: 'New conversation',
      messages: [],
      updatedAt: new Date(),
    }
    setConversations(prev => [newConv, ...prev])
    setCurrentConvId(newConv.id)
    setMessages([])
    setInput('')
    setCurrentView('chat')
    closeSidebarOnMobile()
    inputRef.current?.focus()
  }

  const switchConversation = (conv: Conversation) => {
    setCurrentConvId(conv.id)
    setMessages(conv.messages)
    setCurrentView('chat')
    closeSidebarOnMobile()
  }

  const updateCurrentConversation = (newMessages: Message[], title?: string) => {
    if (!currentConvId) return

    setConversations(prev =>
      prev.map(conv => {
        if (conv.id === currentConvId) {
          const firstUserMsg = newMessages.find(m => m.role === 'user')
          const newTitle = title || (firstUserMsg ? firstUserMsg.content.slice(0, 48) + (firstUserMsg.content.length > 48 ? '...' : '') : conv.title)
          return {
            ...conv,
            messages: newMessages,
            title: newTitle,
            updatedAt: new Date(),
          }
        }
        return conv
      })
    )
  }

  const sendMessage = async (content: string) => {
    if (!content.trim() || isLoading) return

    const userMessage: Message = {
      id: 'u-' + Date.now(),
      role: 'user',
      content: content.trim(),
      timestamp: new Date(),
    }

    const newMessages = [...messages, userMessage]
    setMessages(newMessages)
    setInput('')
    setIsLoading(true)

    // Update conv immediately
    updateCurrentConversation(newMessages)

    try {
      const modelConfig = availableModels.find(m => m.id === selectedModel) || { provider: 'openai' }
      
      const res = await fetch(`${API_BASE}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          messages: newMessages.map(m => ({ role: m.role, content: m.content })),
          model: selectedModel,
          provider: modelConfig.provider,
        }),
      })

      if (!res.ok) {
        const err = await res.text()
        throw new Error(err || 'Chat request failed')
      }

      const data = await res.json()

      if (Array.isArray(data.pendingAccessRequests) && data.pendingAccessRequests.length > 0) {
        setPendingAccessRequests(prev => {
          const byId = new Map(prev.map(p => [p.requestId, p]))
          for (const item of data.pendingAccessRequests as PendingAccessRequest[]) {
            if (!item?.requestId) continue
            byId.set(item.requestId, { ...byId.get(item.requestId), ...item })
          }
          const next = Array.from(byId.values()).filter(p => !isTerminalAccessRequestStatus(p.status))
          localStorage.setItem(PENDING_STORAGE_KEY, JSON.stringify(next))
          // Restore server-side action context for fulfillment after restarts
          for (const item of next) {
            if (item.action?.type) {
              fetch(`${API_BASE}/api/agent/access-request/${encodeURIComponent(item.requestId)}/context`, {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: item.action, description: item.description }),
              }).catch(() => {})
            }
          }
          return next
        })
      }
      
      const assistantMessage: Message = {
        id: 'a-' + Date.now(),
        role: 'assistant',
        content: data.content || 'Sorry, I had trouble generating a response.',
        timestamp: new Date(),
      }

      const finalMessages = [...newMessages, assistantMessage]
      setMessages(finalMessages)
      updateCurrentConversation(finalMessages)

    } catch (error: any) {
      console.error('Chat error:', error)
      const errorMsg: Message = {
        id: 'err-' + Date.now(),
        role: 'assistant',
        content: `**Error:** ${error.message}`,
        timestamp: new Date(),
      }
      const finalMessages = [...newMessages, errorMsg]
      setMessages(finalMessages)
      updateCurrentConversation(finalMessages)
      toast.error('Chat request failed')
    } finally {
      setIsLoading(false)
      inputRef.current?.focus()
    }
  }

  const handleSend = () => {
    sendMessage(input)
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const copyMessage = async (content: string, id: string) => {
    await navigator.clipboard.writeText(content)
    setCopiedId(id)
    toast.success('Copied to clipboard')
    setTimeout(() => setCopiedId(null), 1500)
  }

  const handleSuggestedPrompt = (prompt: string) => {
    sendMessage(prompt)
  }

  const handleQuickAction = async (actionId: string) => {
    const action = QUICK_ACTIONS.find(a => a.id === actionId)
    if (!action) return

    setCurrentView('chat')

    // Fire a message that also calls the action endpoint in parallel
    const actionMsg = `Trigger quick action: **${action.label}**`
    
    // Call backend action (fire and forget for demo)
    fetch(`${API_BASE}/api/actions/` + actionId, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ requestedBy: currentUser.email }),
    }).catch(() => {})

    sendMessage(actionMsg)
    toast.info(`Action "${action.label}" submitted (demo - approval workflow would trigger in production)`)
  }

  const deleteConversation = (id: string, e: React.MouseEvent) => {
    e.stopPropagation()
    if (conversations.length === 1) {
      toast.error('Cannot delete the last conversation')
      return
    }
    const remaining = conversations.filter(c => c.id !== id)
    setConversations(remaining)
    if (currentConvId === id) {
      setCurrentConvId(remaining[0].id)
      setMessages(remaining[0].messages)
    }
  }

  // Render a single message with markdown + copy
  const renderMessage = (msg: Message) => {
    const isUser = msg.role === 'user'
    return (
      <div key={msg.id} className={`flex ${isUser ? 'justify-end' : 'justify-start'} mb-6 group`}>
        <div className={`message-bubble ${isUser ? 'user-message' : 'assistant-message'}`}>
          <div className="prose prose-invert prose-sm max-w-none">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>
              {msg.content}
            </ReactMarkdown>
          </div>
          <div className="flex items-center justify-between mt-1.5 opacity-60 text-[10px]">
            <span>{msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
            {!isUser && (
              <button
                onClick={() => copyMessage(msg.content, msg.id)}
                className="copy-btn ml-2 p-1 hover:bg-white/10 rounded"
                title="Copy"
              >
                {copiedId === msg.id ? <Check size={13} /> : <Copy size={13} />}
              </button>
            )}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-[#0f0f12] text-[#f4f4f5]">
      <Toaster position="top-center" richColors closeButton />

      {/* Top Header */}
      <header className="portal-header flex items-center justify-between px-4 sm:px-6 lg:px-8 z-50">
        <div className="header-left">
          {authStatus === 'authenticated' && (
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="p-2 rounded-lg hover:bg-[#27272a] text-[#a1a1aa] transition-colors shrink-0"
              aria-label={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
            >
              {sidebarOpen ? <ChevronLeft size={18} /> : <ChevronRight size={18} />}
            </button>
          )}
          <div className="header-brand">
            <div className="w-9 h-9 rounded-lg bg-[#f97316] flex items-center justify-center text-black font-bold text-lg shadow-sm shrink-0">SD</div>
            <div>
              <div className="logo text-xl tracking-tight">Super Duper Admin Portal</div>
              <div className="text-[11px] text-[#a1a1aa] mt-0.5 leading-snug">sledai.oktapreview.com</div>
            </div>
          </div>
          {authStatus === 'authenticated' && (
            <div className="header-status">
              <div className="status-dot" />
              <span className="text-[#22c55e] text-xs font-medium">CONNECTED</span>
            </div>
          )}
        </div>

        {authStatus === 'authenticated' && (
          <div className="header-right text-sm">
            <div className="header-user-block">
              <div className="font-medium">{currentUser.name}</div>
              <div className="text-[11px] text-[#a1a1aa] mt-0.5">{currentUser.role}</div>
            </div>
            <div className="header-divider" />
            <div className="w-9 h-9 rounded-full bg-[#f97316]/15 border border-[#f97316]/20 flex items-center justify-center text-[#f97316] shrink-0">
              <User size={16} />
            </div>
            <button
              onClick={() => {
                window.location.href = `${API_BASE}/api/logout`
              }}
              className="p-2.5 rounded-lg text-[#a1a1aa] hover:text-white hover:bg-[#27272a] transition-colors shrink-0"
              title="Log out"
            >
              <LogOut size={17} />
            </button>
          </div>
        )}
      </header>

      {/* Loading state */}
      {authStatus === 'loading' && (
        <div className="flex items-center justify-center min-h-[calc(100vh-68px)] bg-[#0f0f12]">
          <div className="text-[#a1a1aa]">Loading...</div>
        </div>
      )}

      {/* Splash page for unauthenticated users (SP-initiated flow) */}
      {authStatus === 'unauthenticated' && (
        <div className="flex flex-col items-center justify-center min-h-[calc(100vh-68px)] bg-[#0f0f12] text-center px-8 py-16">
          <div className="max-w-md w-full">
            <div className="flex items-center justify-center gap-4 mb-10">
              <div className="w-14 h-14 rounded-xl bg-[#f97316] flex items-center justify-center text-black font-bold text-3xl shadow-md">SD</div>
              <div className="text-left">
                <div className="text-3xl font-semibold tracking-tight leading-tight">Super Duper Admin Portal</div>
                <div className="text-sm text-[#a1a1aa] mt-1">sledai.oktapreview.com</div>
              </div>
            </div>

            <h1 className="text-2xl font-semibold mb-4 tracking-tight">Welcome, Okta Admin</h1>
            <p className="text-[#a1a1aa] mb-10 leading-relaxed">
              This portal is restricted to authorized administrators of the sledai.oktapreview.com organization.
            </p>

            <div className="flex justify-center">
              <button
                type="button"
                onClick={() => {
                  window.location.href = `${API_BASE}/api/oidc/login`
                }}
                className="sign-in-btn"
              >
                <User size={18} /> Sign in with Okta
              </button>
            </div>

            <p className="text-[11px] text-[#71717a] mt-8">
              You will be redirected to Okta to authenticate.
            </p>
          </div>
        </div>
      )}

      {/* Main authenticated app */}
      {authStatus !== 'unauthenticated' && (
      <div className="flex flex-1 overflow-hidden px-3 py-3 gap-3 sm:px-6 sm:py-5 sm:gap-6">
        {/* Mobile drawer backdrop */}
        {sidebarOpen && (
          <div
            className="sidebar-backdrop"
            onClick={() => setSidebarOpen(false)}
            aria-hidden="true"
          />
        )}
        {/* Sidebar */}
        {sidebarOpen && (
          <div className="sidebar w-80 flex-shrink-0 flex flex-col overflow-hidden">
            {/* New Chat */}
            <div className="pb-4 mb-3 border-b border-[#3f3f46]/50">
              <button
                onClick={createNewChat}
                className="btn-primary w-full flex items-center justify-center gap-2 py-3 rounded-xl text-sm"
              >
                <Plus size={16} /> New Chat
              </button>
            </div>

            {/* Conversations */}
            <div className="flex-1 overflow-y-auto py-1 text-sm min-h-0">
              <div className="sidebar-section-label">Conversations</div>
              {conversations.length === 0 && (
                <div className="text-[#71717a] text-xs px-3 py-3">No conversations yet</div>
              )}
              {conversations.map(conv => (
                <div
                  key={conv.id}
                  onClick={() => switchConversation(conv)}
                  className={`sidebar-item flex items-center justify-between gap-2 px-3 py-3 cursor-pointer mb-1.5 text-sm ${currentConvId === conv.id ? 'active' : ''}`}
                >
                  <div className="truncate pr-2 flex items-center gap-2">
                    <MessageSquare size={15} className="shrink-0" />
                    <span className="truncate">{conv.title}</span>
                  </div>
                  {conversations.length > 1 && (
                    <button onClick={(e) => deleteConversation(conv.id, e)} className="opacity-40 hover:opacity-100 text-xs">×</button>
                  )}
                </div>
              ))}
            </div>

            {/* Nav */}
            <div className="border-t border-[#3f3f46]/50 pt-4 mt-3 text-sm space-y-1.5">
              <div className="sidebar-section-label mb-2">Navigation</div>
              <div
                onClick={() => { setCurrentView('chat'); closeSidebarOnMobile() }}
                className={`sidebar-item flex items-center gap-3 px-3 py-3 cursor-pointer ${currentView === 'chat' ? 'active' : ''}`}
              >
                <MessageSquare size={16} /> Chat
              </div>
              <div
                onClick={() => { setCurrentView('actions'); closeSidebarOnMobile() }}
                className={`sidebar-item flex items-center gap-3 px-3 py-3 cursor-pointer ${currentView === 'actions' ? 'active' : ''}`}
              >
                <Zap size={16} /> Quick Actions
              </div>
              <div
                onClick={() => { setCurrentView('users'); toast('Users view coming soon – uses /api/okta/users'); closeSidebarOnMobile() }}
                className={`sidebar-item flex items-center gap-3 px-3 py-3 cursor-pointer ${currentView === 'users' ? 'active' : ''}`}
              >
                <User size={16} /> Users &amp; Groups
              </div>
              <div
                onClick={() => { setCurrentView('settings'); closeSidebarOnMobile() }}
                className={`sidebar-item flex items-center gap-3 px-3 py-3 cursor-pointer ${currentView === 'settings' ? 'active' : ''}`}
              >
                <Settings size={16} /> Settings
              </div>
            </div>

            <div className="pt-4 mt-3 text-[10px] text-[#71717a] leading-relaxed border-t border-[#3f3f46]/50">
              Demo • OIDC + Okta Workflows ready
            </div>
          </div>
        )}

        {/* Main Content Area */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Chat View */}
          {currentView === 'chat' && (
            <div className="chat-container flex-1 flex flex-col overflow-hidden">
              {/* Chat header / model picker */}
              <div className="panel-header">
                <div>
                  <div className="panel-header-title">Okta Admin Assistant</div>
                  <div className="panel-header-subtitle">sledai.oktapreview.com • Responses may be logged for audit</div>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <select
                    value={selectedModel}
                    onChange={(e) => setSelectedModel(e.target.value)}
                    className="model-select rounded-xl px-4 py-2.5 text-sm focus:outline-none"
                    disabled={availableModels.length === 0}
                  >
                    {availableModels.length === 0 ? (
                      <option value="">No models available</option>
                    ) : (
                      availableModels.map(opt => (
                        <option key={opt.id} value={opt.id}>{opt.label}</option>
                      ))
                    )}
                  </select>
                  <button onClick={createNewChat} className="btn-secondary flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm">
                    <Plus size={15} /> New
                  </button>
                </div>
              </div>

              {/* Messages */}
              <div className="messages-area">
                <div className="messages-inner">
                  {messages.length === 0 && (
                    <div className="empty-state">
                      <div className="empty-state-icon"><Shield size={28} /></div>
                      <h2>Ready when you are</h2>
                      <p>Ask anything about your Okta environment or use a suggested prompt below.</p>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        {SUGGESTED_PROMPTS.map((p, i) => (
                          <button
                            key={i}
                            onClick={() => handleSuggestedPrompt(p)}
                            className="prompt-chip text-left px-5 py-4 rounded-2xl"
                          >
                            {p}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}

                  {messages.map(renderMessage)}

                  {isLoading && (
                    <div className="flex justify-start mb-6">
                      <div className="assistant-message">
                        <div className="typing-indicator">
                          <span></span><span></span><span></span>
                        </div>
                      </div>
                    </div>
                  )}
                  <div ref={messagesEndRef} />
                </div>
              </div>

              {needsReauth && (
                <div className="reauth-banner">
                  <div className="messages-inner flex flex-wrap items-center justify-between gap-3 text-sm">
                    <span>
                      Your Okta token expired (~1 hour). Agent tools (secrets, delegated API) need a fresh sign-in.
                    </span>
                    <button
                      type="button"
                      className="btn-primary px-4 py-2 rounded-xl text-sm shrink-0"
                      onClick={() => { window.location.href = `${API_BASE}/api/oidc/login` }}
                    >
                      Sign in again
                    </button>
                  </div>
                </div>
              )}

              {pendingAccessRequests.some(p => !isTerminalAccessRequestStatus(p.status)) && (
                <div className="access-request-poll-banner">
                  <div className="messages-inner flex items-center gap-2 text-sm">
                    <Shield size={15} className="shrink-0 text-[#f97316]" />
                    <span>
                      Waiting for Okta approval:{' '}
                      {pendingAccessRequests
                        .filter(p => !isTerminalAccessRequestStatus(p.status))
                        .map(p => `${p.requestId.slice(0, 8)}… (${accessRequestStatusLabel(p.status)})`)
                        .join(' · ')}
                    </span>
                  </div>
                </div>
              )}

              {/* Input */}
              <div className="input-area">
                <div className="messages-inner flex gap-3 items-end">
                  <textarea
                    ref={inputRef}
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Ask about users, policies, sign-ins, or request an admin action..."
                    className="chat-input flex-1 rounded-2xl px-5 py-4 min-h-[56px] max-h-36"
                    rows={1}
                    disabled={isLoading}
                  />
                  <button
                    onClick={handleSend}
                    disabled={!input.trim() || isLoading}
                    className="btn-primary h-[56px] w-[56px] rounded-2xl flex items-center justify-center disabled:opacity-50 shrink-0"
                  >
                    <Send size={19} />
                  </button>
                </div>
                <div className="text-center text-[11px] text-[#71717a] mt-3">
                  All destructive actions require Okta workflow approval • Conversations saved locally
                </div>
              </div>
            </div>
          )}

          {/* Quick Actions View */}
          {currentView === 'actions' && (
            <div className="content-panel flex-1 overflow-hidden">
              <div className="content-panel-body">
                <div className="max-w-4xl mx-auto w-full">
                  <h1 className="text-2xl font-semibold mb-2 tracking-tight">Quick Actions</h1>
                  <p className="text-[#a1a1aa] mb-10 leading-relaxed">These trigger backend REST calls. Destructive ones initiate Okta approval workflows.</p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                    {QUICK_ACTIONS.map(action => {
                      const Icon = action.icon
                      return (
                        <button
                          key={action.id}
                          onClick={() => handleQuickAction(action.id)}
                          className={`action-card text-left flex gap-5 ${action.danger ? 'danger' : ''}`}
                        >
                          <div className={`mt-1 shrink-0 ${action.danger ? 'text-[#ef4444]' : 'text-[#f97316]'}`}>
                            <Icon size={24} />
                          </div>
                          <div>
                            <div className="font-semibold text-base tracking-tight">{action.label}</div>
                            <div className="text-[#a1a1aa] text-sm mt-2 leading-relaxed">{action.desc}</div>
                            <div className="mt-5 text-xs text-[#f97316] font-medium tracking-wide">EXECUTE →</div>
                          </div>
                        </button>
                      )
                    })}
                  </div>

                  <div className="mt-10 info-card text-sm leading-relaxed">
                    <strong>Production note:</strong> These endpoints will POST to your Okta Workflows or custom approval system. The chat assistant can also trigger them via function calling once the MCP + LLM tools are connected.
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Users placeholder */}
          {currentView === 'users' && (
            <div className="content-panel flex-1 overflow-hidden">
              <div className="content-panel-body flex flex-col items-center justify-center text-center">
                <div className="max-w-md">
                  <div className="w-16 h-16 mx-auto mb-6 rounded-2xl bg-[#27272a] border border-[#3f3f46]/50 flex items-center justify-center">
                    <User size={32} className="text-[#f97316] opacity-80" />
                  </div>
                  <h2 className="text-xl font-semibold tracking-tight">Users &amp; Groups</h2>
                  <p className="text-[#a1a1aa] mt-4 leading-relaxed">This tab will list users via <code className="text-[#f97316] bg-[#27272a] px-1.5 py-0.5 rounded">GET /api/okta/users</code> and support bulk actions. Coming in next iteration.</p>
                  <button onClick={() => setCurrentView('chat')} className="btn-secondary mt-8 px-6 py-3 rounded-xl">Back to Chat</button>
                </div>
              </div>
            </div>
          )}

          {/* Settings */}
          {currentView === 'settings' && (
            <div className="content-panel flex-1 overflow-hidden">
              <div className="content-panel-body">
                <div className="max-w-2xl mx-auto w-full">
                  <h1 className="text-2xl font-semibold mb-2 tracking-tight">Settings</h1>
                  <p className="text-[#a1a1aa] mb-8 leading-relaxed">Portal configuration and integration details.</p>
                  <div className="space-y-5 text-sm">
                    <div className="info-card">
                      <div className="font-medium mb-2 text-base">Authentication Mode</div>
                      <div className="text-[#a1a1aa]">Currently: <span className="text-[#f97316]">OIDC (private_key_jwt)</span></div>
                      <div className="text-xs mt-3 leading-relaxed text-[#a1a1aa]">Users launch this app from the Okta dashboard, sign in via OIDC, and the agent acts on their behalf (human ∩ agent scopes) through Cross App Access.</div>
                    </div>
                    <div className="info-card">
                      <div className="font-medium mb-2 text-base">LLM Configuration</div>
                      <div className="text-[#a1a1aa] leading-relaxed">Keys are loaded server-side from <code className="text-[#f97316] bg-[#1f1f23] px-1.5 py-0.5 rounded">.env</code>. Add OPENAI_API_KEY etc. then restart api process.</div>
                    </div>
                    <div className="info-card">
                      <div className="font-medium mb-2 text-base">MCP Server</div>
                      <div className="text-[#a1a1aa] leading-relaxed">A Model Context Protocol server will expose these chat + action tools to agents (Claude Desktop, etc).</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
      )}
    </div>
  )
}

export default App

