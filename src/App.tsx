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
  const [sidebarOpen, setSidebarOpen] = useState(true)
  
  // Chat State
  const [conversations, setConversations] = useState<Conversation[]>([])
  const [currentConvId, setCurrentConvId] = useState<string | null>(null)
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [selectedModel, setSelectedModel] = useState<string>('')
  const [availableModels, setAvailableModels] = useState<ModelOption[]>([])
  const [copiedId, setCopiedId] = useState<string | null>(null)

  // Auth state for splash page (SP-initiated flow)
  type AuthStatus = 'loading' | 'authenticated' | 'unauthenticated'
  const [authStatus, setAuthStatus] = useState<AuthStatus>('loading')

  // Auth state - supports both DEMO_AUTH_BYPASS and real SAML
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
            role: data.user.authMethod === 'saml' ? 'Super Admin (SAML JIT)' : 'Admin',
          })
          setAuthStatus('authenticated')
        } else {
          setAuthStatus('unauthenticated')
        }
      })
      .catch(() => {
        setAuthStatus('unauthenticated')
      })
      .finally(() => setAuthLoading(false))
  }, [])

  const messagesEndRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)

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
    inputRef.current?.focus()
  }

  const switchConversation = (conv: Conversation) => {
    setCurrentConvId(conv.id)
    setMessages(conv.messages)
    setCurrentView('chat')
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
      <div key={msg.id} className={`flex ${isUser ? 'justify-end' : 'justify-start'} mb-5 group`}>
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
      <header className="portal-header flex items-center justify-between px-7 z-50">
        <div className="flex items-center gap-4">
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="p-1.5 rounded hover:bg-[#27272a] text-[#a1a1aa]"
          >
            {sidebarOpen ? <ChevronLeft size={18} /> : <ChevronRight size={18} />}
          </button>
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded bg-[#f97316] flex items-center justify-center text-black font-bold text-lg">SD</div>
            <div>
              <div className="logo text-xl tracking-tight">Super Duper Admin Portal</div>
              <div className="text-[10px] text-[#a1a1aa] -mt-1">sledai.oktapreview.com</div>
            </div>
          </div>
          <div className="ml-4 px-2.5 py-0.5 text-xs rounded-full bg-[#27272a] border border-[#3f3f46] flex items-center gap-1.5">
            <div className="status-dot" />
            <span className="text-[#22c55e] text-xs font-medium">CONNECTED</span>
          </div>
        </div>

        {authStatus === 'authenticated' && (
          <div className="flex items-center gap-4 text-sm">
            <div className="text-right">
              <div className="font-medium">{currentUser.name}</div>
              <div className="text-[11px] text-[#a1a1aa]">{currentUser.role}</div>
            </div>
            <div className="w-8 h-8 rounded-full bg-[#f97316]/20 flex items-center justify-center text-[#f97316]">
              <User size={16} />
            </div>
            <button
              onClick={() => {
                // Proper logout: call backend to destroy session, then go to root (splash)
                window.location.href = `${API_BASE}/api/saml/logout`
              }}
              className="p-2 text-[#a1a1aa] hover:text-white"
              title="Log out"
            >
              <LogOut size={17} />
            </button>
          </div>
        )}
      </header>

      {/* Loading state */}
      {authStatus === 'loading' && (
        <div className="flex items-center justify-center min-h-[calc(100vh-64px)] bg-[#0f0f12]">
          <div className="text-[#a1a1aa]">Loading...</div>
        </div>
      )}

      {/* Splash page for unauthenticated users (SP-initiated flow) */}
      {authStatus === 'unauthenticated' && (
        <div className="flex flex-col items-center justify-center min-h-[calc(100vh-64px)] bg-[#0f0f12] text-center p-8">
          <div className="max-w-md">
            <div className="flex items-center justify-center gap-3 mb-6">
              <div className="w-12 h-12 rounded bg-[#f97316] flex items-center justify-center text-black font-bold text-3xl">SD</div>
              <div className="text-left">
                <div className="text-3xl font-semibold tracking-tight">Super Duper Admin Portal</div>
                <div className="text-sm text-[#a1a1aa]">sledai.oktapreview.com</div>
              </div>
            </div>

            <h1 className="text-2xl font-semibold mb-3">Welcome, Okta Admin</h1>
            <p className="text-[#a1a1aa] mb-8">
              This portal is restricted to authorized administrators of the sledai.oktapreview.com organization.
            </p>

            <button
              onClick={() => {
                window.location.href = `${API_BASE}/api/saml/login`
              }}
              className="mx-auto block max-w-xs w-full py-3.5 rounded-2xl bg-[#f97316] hover:bg-[#ea580c] active:bg-[#c2410c] text-white text-base font-semibold transition-all flex items-center justify-center gap-2 shadow-sm hover:shadow-md"
            >
              <User size={18} /> Sign in with Okta
            </button>

            <p className="text-[11px] text-[#71717a] mt-6">
              You will be redirected to Okta to authenticate.
            </p>
          </div>
        </div>
      )}

      {/* Main authenticated app */}
      {authStatus !== 'unauthenticated' && (
      <div className="flex flex-1 overflow-hidden p-5 gap-5">
        {/* Sidebar */}
        {sidebarOpen && (
          <div className="sidebar w-72 flex-shrink-0 flex flex-col overflow-hidden rounded-2xl">
            {/* New Chat */}
            <div className="pb-3 mb-1 border-b border-[#3f3f46]/60">
              <button
                onClick={createNewChat}
                className="btn-primary w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-sm"
              >
                <Plus size={16} /> New Chat
              </button>
            </div>

            {/* Conversations */}
            <div className="flex-1 overflow-y-auto py-2 text-sm">
              <div className="px-2 pb-1.5 text-[10px] uppercase tracking-widest text-[#71717a] font-semibold">Conversations</div>
              {conversations.length === 0 && (
                <div className="text-[#71717a] text-xs px-3 py-2">No conversations yet</div>
              )}
              {conversations.map(conv => (
                <div
                  key={conv.id}
                  onClick={() => switchConversation(conv)}
                  className={`sidebar-item flex items-center justify-between gap-2 px-3 py-2.5 rounded-xl cursor-pointer mb-1 text-sm ${currentConvId === conv.id ? 'active' : ''}`}
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
            <div className="border-t border-[#3f3f46]/60 pt-2 mt-1 text-sm space-y-1">
              <div
                onClick={() => setCurrentView('chat')}
                className={`sidebar-item flex items-center gap-2.5 px-3 py-2.5 rounded-xl cursor-pointer ${currentView === 'chat' ? 'active' : ''}`}
              >
                <MessageSquare size={16} /> Chat
              </div>
              <div
                onClick={() => setCurrentView('actions')}
                className={`sidebar-item flex items-center gap-2.5 px-3 py-2.5 rounded-xl cursor-pointer ${currentView === 'actions' ? 'active' : ''}`}
              >
                <Zap size={16} /> Quick Actions
              </div>
              <div
                onClick={() => { setCurrentView('users'); toast('Users view coming soon – uses /api/okta/users') }}
                className={`sidebar-item flex items-center gap-2.5 px-3 py-2.5 rounded-xl cursor-pointer ${currentView === 'users' ? 'active' : ''}`}
              >
                <User size={16} /> Users &amp; Groups
              </div>
              <div
                onClick={() => setCurrentView('settings')}
                className={`sidebar-item flex items-center gap-2.5 px-3 py-2.5 rounded-xl cursor-pointer ${currentView === 'settings' ? 'active' : ''}`}
              >
                <Settings size={16} /> Settings
              </div>
            </div>

            <div className="pt-3 mt-1 text-[10px] text-[#71717a] border-t border-[#3f3f46]/60">
              Demo • SAML + Okta Workflows ready
            </div>
          </div>
        )}

        {/* Main Content Area */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Chat View */}
          {currentView === 'chat' && (
            <div className="chat-container flex-1 flex flex-col rounded-2xl overflow-hidden">
              {/* Chat header / model picker */}
              <div className="flex items-center justify-between px-6 py-4 border-b border-[#3f3f46]/60 bg-[#18181b]">
                <div>
                  <div className="font-semibold">Okta Admin Assistant</div>
                  <div className="text-xs text-[#a1a1aa] mt-0.5">sledai.oktapreview.com • Responses may be logged for audit</div>
                </div>
                <div className="flex items-center gap-3">
                  <select
                    value={selectedModel}
                    onChange={(e) => setSelectedModel(e.target.value)}
                    className="model-select rounded-xl px-3.5 py-2 text-sm focus:outline-none"
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
                  <button onClick={createNewChat} className="btn-secondary flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-sm">
                    <Plus size={15} /> New
                  </button>
                </div>
              </div>

              {/* Messages */}
              <div className="messages-area">
                {messages.length === 0 && (
                  <div className="max-w-2xl mx-auto mt-12 text-center">
                    <div className="text-6xl mb-5">👋</div>
                    <h2 className="text-2xl font-semibold mb-2.5">Ready when you are</h2>
                    <p className="text-[#a1a1aa] mb-8">Ask anything about your Okta environment or use a suggested prompt below.</p>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-w-xl mx-auto">
                      {SUGGESTED_PROMPTS.map((p, i) => (
                        <button
                          key={i}
                          onClick={() => handleSuggestedPrompt(p)}
                          className="prompt-chip text-left px-4 py-3.5 rounded-2xl"
                        >
                          {p}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {messages.map(renderMessage)}

                {isLoading && (
                  <div className="flex justify-start mb-4">
                    <div className="assistant-message">
                      <div className="typing-indicator">
                        <span></span><span></span><span></span>
                      </div>
                    </div>
                  </div>
                )}
                <div ref={messagesEndRef} />
              </div>

              {/* Input */}
              <div className="input-area">
                <div className="max-w-4xl mx-auto flex gap-2 items-end">
                  <textarea
                    ref={inputRef}
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Ask about users, policies, sign-ins, or request an admin action..."
                    className="chat-input flex-1 rounded-2xl px-5 py-3.5 min-h-[52px] max-h-36"
                    rows={1}
                    disabled={isLoading}
                  />
                  <button
                    onClick={handleSend}
                    disabled={!input.trim() || isLoading}
                    className="btn-primary h-[52px] w-[52px] rounded-2xl flex items-center justify-center disabled:opacity-50"
                  >
                    <Send size={19} />
                  </button>
                </div>
                <div className="text-center text-[10px] text-[#71717a] mt-2">
                  All destructive actions require Okta workflow approval • Conversations saved locally
                </div>
              </div>
            </div>
          )}

          {/* Quick Actions View */}
          {currentView === 'actions' && (
            <div className="p-10 max-w-4xl mx-auto w-full overflow-y-auto">
              <h1 className="text-2xl font-semibold mb-1.5">Quick Actions</h1>
              <p className="text-[#a1a1aa] mb-8">These trigger backend REST calls. Destructive ones initiate Okta approval workflows.</p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                {QUICK_ACTIONS.map(action => {
                  const Icon = action.icon
                  return (
                    <button
                      key={action.id}
                      onClick={() => handleQuickAction(action.id)}
                      className={`action-card text-left rounded-2xl flex gap-4 ${action.danger ? 'danger' : ''}`}
                    >
                      <div className={`mt-0.5 ${action.danger ? 'text-[#ef4444]' : 'text-[#f97316]'}`}>
                        <Icon size={26} />
                      </div>
                      <div>
                        <div className="font-semibold text-lg">{action.label}</div>
                        <div className="text-[#a1a1aa] text-sm mt-1">{action.desc}</div>
                        <div className="mt-4 text-xs text-[#f97316] font-medium tracking-wide">EXECUTE →</div>
                      </div>
                    </button>
                  )
                })}
              </div>

              <div className="mt-8 p-5 rounded-2xl bg-[#18181b] border border-[#3f3f46]/60 text-sm leading-relaxed">
                <strong>Production note:</strong> These endpoints will POST to your Okta Workflows or custom approval system. The chat assistant can also trigger them via function calling once the MCP + LLM tools are connected.
              </div>
            </div>
          )}

          {/* Users placeholder */}
          {currentView === 'users' && (
            <div className="p-10 max-w-3xl mx-auto text-center flex flex-col items-center justify-center h-full">
              <User size={48} className="mx-auto mb-5 opacity-60" />
              <h2 className="text-xl font-semibold">Users &amp; Groups</h2>
              <p className="text-[#a1a1aa] mt-2.5 max-w-md leading-relaxed">This tab will list users via <code className="text-[#f97316]">GET /api/okta/users</code> and support bulk actions. Coming in next iteration.</p>
              <button onClick={() => setCurrentView('chat')} className="btn-secondary mt-7 px-6 py-2.5 rounded-xl">Back to Chat</button>
            </div>
          )}

          {/* Settings */}
          {currentView === 'settings' && (
            <div className="p-10 max-w-2xl mx-auto w-full overflow-y-auto">
              <h1 className="text-2xl font-semibold mb-6">Settings</h1>
              <div className="space-y-4 text-sm">
                <div className="p-5 bg-[#18181b] rounded-2xl border border-[#3f3f46]/60">
                  <div className="font-medium mb-1.5">Authentication Mode</div>
                  <div className="text-[#a1a1aa]">Currently: <span className="text-[#f97316]">DEMO_AUTH_BYPASS</span> (SAML coming)</div>
                  <div className="text-xs mt-2.5 leading-relaxed">When SAML is enabled in Okta, users will launch this app from the dashboard and JIT into full admin rights here.</div>
                </div>
                <div className="p-5 bg-[#18181b] rounded-2xl border border-[#3f3f46]/60">
                  <div className="font-medium mb-1.5">LLM Configuration</div>
                  <div className="text-[#a1a1aa] leading-relaxed">Keys are loaded server-side from <code>.env</code>. Add OPENAI_API_KEY etc. then restart api process.</div>
                </div>
                <div className="p-5 bg-[#18181b] rounded-2xl border border-[#3f3f46]/60">
                  <div className="font-medium mb-1.5">MCP Server</div>
                  <div className="text-[#a1a1aa] leading-relaxed">A Model Context Protocol server will expose these chat + action tools to agents (Claude Desktop, etc).</div>
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

