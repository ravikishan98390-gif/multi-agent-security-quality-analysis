import React, { useState, useEffect, useRef } from 'react';
import ReactMarkdown from 'react-markdown';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { atomDark } from 'react-syntax-highlighter/dist/esm/styles/prism';

/**
 * CodeAssistantModal
 * 
 * Full-screen modal overlay with chat on left, code on right.
 * Includes realistic mock conversation showing multi-turn exchanges,
 * code fixes, and OWASP citations.
 */

// Mock conversation data showing the complete flow
const MOCK_CONVERSATION_PYTHON = [
  {
    role: 'assistant',
    content: 'I can help you fix these security issues. I found **3 critical vulnerabilities** and **2 code quality issues**. What would you like to focus on first?',
    assistantData: {
      answer: 'I can help you fix these security issues. I found **3 critical vulnerabilities** and **2 code quality issues**. What would you like to focus on first?',
      referencedFindingIds: [],
      codeFix: null,
      sources: []
    }
  },
  {
    role: 'user',
    content: 'Why is the SQL Injection on line 15 critical?'
  },
  {
    role: 'assistant',
    content: 'SQL injection is **CRITICAL** because attackers can manipulate SQL queries to bypass authentication, extract sensitive data, or delete records.',
    assistantData: {
      answer: `## SQL Injection Vulnerability (Line 15)

Your code directly concatenates user input into SQL:

\`\`\`python
query = f"SELECT * FROM users WHERE username = '{username}'"
\`\`\`

An attacker could input: \`' OR '1'='1\` to extract all users instead of searching.

This violates **OWASP A03:2021 - Injection**, one of the most dangerous vulnerability classes.

**Why it's CRITICAL:**
- Attackers can bypass authentication
- Extract entire databases
- Modify/delete data
- Potentially execute commands on the server

**The fix:** Use parameterized queries (prepared statements).`,
      referencedFindingIds: ['F001'],
      codeFix: {
        before: `import mysql.connector

conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="admin123"  # HARDCODED!
)

cursor = conn.cursor()
username = request.args.get('username')
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)`,
        after: `import mysql.connector

conn = mysql.connector.connect(
    host="localhost",
    user=os.getenv('DB_USER'),
    password=os.getenv('DB_PASSWORD')
)

cursor = conn.cursor()
username = request.args.get('username')
query = "SELECT * FROM users WHERE username = %s"
cursor.execute(query, (username,))`,
        explanation: "Parameterized queries separate SQL logic from data. The %s placeholder is safely replaced by the JDBC/database driver, preventing injection."
      },
      sources: [
        {
          title: 'OWASP A03:2021 - Injection',
          snippet: 'Injection flaws occur when untrusted data is sent to an interpreter. Use parameterized queries for all database access.'
        },
        {
          title: 'CWE-89: SQL Injection',
          snippet: 'SQL injection attacks allow attackers to interfere with database queries, compromising data integrity and confidentiality.'
        }
      ]
    }
  },
  {
    role: 'user',
    content: 'What about line 4 - the hardcoded password?'
  },
  {
    role: 'assistant',
    content: 'Hardcoding credentials is a **CRITICAL** security breach that exposes your database to anyone with code access.',
    assistantData: {
      answer: `## Hardcoded Secret (Line 4)

**CRITICAL ISSUE:** Your database password is hardcoded in the source:

\`\`\`python
password="admin123"
\`\`\`

**Why this is dangerous:**
- ⚠️ Visible in git history (even if deleted later)
- 🔓 Exposed if repository is compromised
- 📋 Anyone with code access can read it
- ❌ Violates OWASP A02:2021 - Cryptographic Failures

**Solutions:**

### ✅ Best Practice: Environment Variables
Load secrets from environment variables set by your deployment platform:

\`\`\`python
import os
password = os.getenv('DB_PASSWORD')
\`\`\`

Then set in .env (NOT committed):
\`\`\`
DB_PASSWORD=your_actual_password
\`\`\`

### ✅ Alternative: Secrets Manager
Use AWS Secrets Manager, HashiCorp Vault, or Azure Key Vault for production.`,
      referencedFindingIds: ['F002'],
      codeFix: null,
      sources: [
        {
          title: 'OWASP A02:2021 - Cryptographic Failures',
          snippet: 'Never store credentials in source code. Use environment variables or secrets management systems.'
        },
        {
          title: '12-Factor App Methodology',
          snippet: 'Store configuration that varies between deploys in environment variables.'
        }
      ]
    }
  },
  {
    role: 'user',
    content: 'Can you show me a fully secure version of this login function?'
  },
  {
    role: 'assistant',
    content: 'Here\'s a secure implementation following OWASP best practices.',
    assistantData: {
      answer: `Here's the complete secure implementation:`,
      referencedFindingIds: ['F001', 'F002', 'F003'],
      codeFix: {
        before: `import mysql.connector

password = "admin123"  # HARDCODED!

def login(username, password):
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password=password
    )
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    return user is not None`,
        after: `import mysql.connector
import os
import bcrypt
from dotenv import load_dotenv

load_dotenv()

def login(username, password_input):
    # Use environment variables for credentials
    db_host = os.getenv('DB_HOST', 'localhost')
    db_user = os.getenv('DB_USER', 'root')
    db_password = os.getenv('DB_PASSWORD')
    
    conn = mysql.connector.connect(
        host=db_host,
        user=db_user,
        password=db_password
    )
    cursor = conn.cursor()
    
    # 1. Use parameterized query (prevents SQL injection)
    query = "SELECT id, username, password_hash FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if user is None:
        return None  # User not found
    
    # 2. Use bcrypt to verify password (not plain text)
    user_id, db_username, password_hash = user
    if bcrypt.checkpw(password_input.encode(), password_hash.encode()):
        return {'id': user_id, 'username': db_username}
    
    return None  # Wrong password`,
        explanation: `**Security improvements:**
1. **Environment variables** for credentials (not hardcoded)
2. **Parameterized query** prevents SQL injection
3. **bcrypt hashing** for password verification (not plain text)
4. **Proper error handling** (doesn't leak info about user existence)
5. **Connection cleanup** to prevent resource leaks`
      },
      sources: [
        {
          title: 'OWASP Authentication Cheat Sheet',
          snippet: 'Use strong password hashing algorithms like bcrypt, scrypt, or Argon2. Never store plain-text passwords.'
        },
        {
          title: 'OWASP Secure Coding Practices',
          snippet: 'Validate all inputs, use parameterized queries, and never trust user data.'
        }
      ]
    }
  }
];

const CodeAssistantModal = ({ isOpen, findings, submission, jobId, initialMessage, onClose, clearInitialMessage }) => {
  const [messages, setMessages] = useState([]);
  const [inputValue, setInputValue] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [highlightedLine, setHighlightedLine] = useState(null);
  const [isMobile, setIsMobile] = useState(window.innerWidth < 1024);
  const [showCode, setShowCode] = useState(true);
  const messagesEndRef = useRef(null);
  const modalRef = useRef(null);
  const focusTrapRef = useRef(null);

  // Initialize with mock conversation only once
  useEffect(() => {
    setMessages([MOCK_CONVERSATION_PYTHON[0]]);
  }, []);

  useEffect(() => {
    if (initialMessage && isOpen) {
      handleInitialMessage(initialMessage);
      if (clearInitialMessage) clearInitialMessage();
    }
  }, [initialMessage, isOpen]);

  // Auto-scroll to latest message
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Handle window resize
  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth < 1024);
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // Close on Escape key
  useEffect(() => {
    const handleEscape = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleEscape);
    return () => window.removeEventListener('keydown', handleEscape);
  }, [onClose]);

  // Focus trap
  useEffect(() => {
    if (modalRef.current) {
      const prev = document.activeElement;
      const modal = modalRef.current;
      const focusableElements = modal.querySelectorAll(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      );
      if (focusableElements.length > 0) {
        focusableElements[0].focus();
      }

      return () => {
        if (prev instanceof HTMLElement) prev.focus();
      };
    }
  }, []);

  const handleInitialMessage = (message) => {
    const userMsg = { role: 'user', content: message };
    setMessages(prev => [...prev, userMsg]);
    setIsLoading(true);

    // Simulate API call with mock data
    setTimeout(() => {
      const response = MOCK_CONVERSATION_PYTHON.find(m => m.role === 'assistant' && m.content.toLowerCase().includes(extractKeyword(message).toLowerCase()));
      if (response) {
        setMessages(prev => [...prev, response]);
      }
      setIsLoading(false);
    }, 1200);
  };

  const extractKeyword = (msg) => {
    if (msg.includes('SQL')) return 'SQL Injection';
    if (msg.includes('password') || msg.includes('hardcoded')) return 'hardcoded';
    if (msg.includes('secure')) return 'secure version';
    return msg;
  };

  const handleSendMessage = () => {
    if (!inputValue.trim()) return;

    const userMsg = { role: 'user', content: inputValue };
    setMessages(prev => [...prev, userMsg]);
    setInputValue('');
    setIsLoading(true);

      setTimeout(() => {
        const responses = MOCK_CONVERSATION_PYTHON.filter(m => m.role === 'assistant');
        const randomResponse = responses[Math.floor(Math.random() * responses.length)];
        setMessages(prev => [...prev, randomResponse]);
        setIsLoading(false);
      }, 1200);
    }, 500); // Small delay to show user message first
  };

  const handleFollowUpClick = (suggestion) => {
    setInputValue(suggestion);
    // Let state update, then send
    setTimeout(() => {
      document.getElementById('send-btn')?.click();
    }, 0);
  };

  const handleCodeLineClick = (lineNumber) => {
    setHighlightedLine(lineNumber);
    setInputValue(`Explain the issue on line ${lineNumber}`);
  };

  // Count findings by severity
  const severityCounts = {
    Critical: findings.filter(f => f.severity === 'Critical').length,
    High: findings.filter(f => f.severity === 'High').length,
    Medium: findings.filter(f => f.severity === 'Medium').length,
    Low: findings.filter(f => f.severity === 'Low').length,
  };

  const code = submission?.code || '';
  const fileName = submission?.filename || 'untitled.py';
  const language = submission?.language || 'python';

  return (
    <div style={{ display: isOpen ? 'block' : 'none', position: 'fixed', zIndex: 9999 }}>
      {/* Backdrop */}
      <div
        style={styles.backdrop}
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Modal */}
      <div
        ref={modalRef}
        style={styles.modal}
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
      >
        {/* Header */}
        <div style={styles.modalHeader}>
          <div>
            <h2 style={styles.modalTitle} id="modal-title">
              {fileName}
            </h2>
            <div style={styles.severityRow}>
              {severityCounts.Critical > 0 && (
                <span style={{ ...styles.severityTag, borderColor: '#dc2626', color: '#dc2626' }}>
                  🔴 {severityCounts.Critical} Critical
                </span>
              )}
              {severityCounts.High > 0 && (
                <span style={{ ...styles.severityTag, borderColor: '#f97316', color: '#f97316' }}>
                  🟠 {severityCounts.High} High
                </span>
              )}
              {severityCounts.Medium > 0 && (
                <span style={{ ...styles.severityTag, borderColor: '#eab308', color: '#eab308' }}>
                  🟡 {severityCounts.Medium} Medium
                </span>
              )}
            </div>
          </div>

          <div style={styles.headerActions}>
            {isMobile && (
              <button
                onClick={() => setShowCode(!showCode)}
                style={styles.toggleButton}
                aria-label={showCode ? 'Hide code' : 'Show code'}
              >
                {showCode ? '↙ Hide Code' : '↗ Show Code'}
              </button>
            )}
            <button
              onClick={onClose}
              style={styles.closeButton}
              aria-label="Close modal"
              ref={focusTrapRef}
            >
              ✕
            </button>
          </div>
        </div>

        {/* Body */}
        <div style={styles.modalBody}>
          {/* Left: Chat */}
          <div style={{ ...styles.chatPanel, display: isMobile && !showCode ? 'flex' : 'flex' }}>
            <div style={styles.messagesContainer}>
              {messages.map((msg, idx) => (
                <ChatMessage key={idx} message={msg} onFindingClick={(id) => setHighlightedLine(id)} />
              ))}
              {isLoading && <TypingIndicator />}
              <div ref={messagesEndRef} />
            </div>

            {/* Input */}
            <div style={styles.inputArea}>
              <input
                type="text"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
                placeholder="Follow-up question..."
                style={styles.input}
                disabled={isLoading}
              />
              <button
                id="send-btn"
                onClick={handleSendMessage}
                disabled={isLoading || !inputValue.trim()}
                style={styles.sendBtn}
                aria-label="Send message"
              >
                ➤
              </button>
            </div>
          </div>

          {/* Right: Code (hidden on mobile unless toggled) */}
          {(!isMobile || showCode) && (
            <div style={styles.codePanel}>
              <CodePanelContent
                code={code}
                language={language}
                findings={findings}
                highlightedLine={highlightedLine}
                onLineClick={handleCodeLineClick}
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// CHAT MESSAGE COMPONENT
// ============================================================================

const ChatMessage = ({ message, onFindingClick }) => {
  const isUser = message.role === 'user';
  const data = message.assistantData;

  const getFollowUpSuggestions = (content) => {
    if (content.includes('fix these security issues')) {
      return ['Explain the SQL Injection issue', 'Show me the hardcoded password'];
    }
    if (content.includes('parameterized queries')) {
      return ['Show best practice alternative', 'Any similar issues elsewhere?'];
    }
    if (content.includes('environment variables')) {
      return ['How do I set environment variables?', 'What is a Secrets Manager?'];
    }
    if (content.includes('secure implementation')) {
      return ['How does bcrypt work?', 'Is this production ready?'];
    }
    return ['Any similar issues elsewhere?', 'Show best practice alternative'];
  };

  return (
    <div style={{ ...styles.messageRow, justifyContent: isUser ? 'flex-end' : 'flex-start' }}>
      {!isUser && <div style={styles.botBadge}>🤖</div>}

      <div
        style={{
          ...styles.messageBubble,
          backgroundColor: isUser ? '#6366f1' : '#0f172a',
          borderColor: isUser ? '#4f46e5' : '#334155',
        }}
      >
        {data?.answer ? (
          <>
            <div style={styles.messageMarkdown}>
              <ReactMarkdown>{data.answer}</ReactMarkdown>
            </div>

            {data.codeFix && <CodeFixBlock codeFix={data.codeFix} />}

            {data.sources && data.sources.length > 0 && (
              <SourcesBlock sources={data.sources} />
            )}

            {data.referencedFindingIds && data.referencedFindingIds.length > 0 && (
              <div style={styles.referencedTags}>
                {data.referencedFindingIds.map(id => (
                  <button
                    key={id}
                    onClick={() => onFindingClick(id)}
                    style={styles.referenceTag}
                  >
                    Finding: {id}
                  </button>
                ))}
              </div>
            )}
            
            {/* Follow-up suggestions */}
            <div style={styles.followUpContainer}>
              {getFollowUpSuggestions(data.answer).map((suggestion, idx) => (
                <button
                  key={idx}
                  onClick={() => {
                    const input = document.querySelector('input[placeholder="Follow-up question..."]');
                    if(input) {
                      const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
                      nativeInputValueSetter.call(input, suggestion);
                      const ev = new Event('input', { bubbles: true});
                      input.dispatchEvent(ev);
                      setTimeout(() => document.getElementById('send-btn')?.click(), 50);
                    }
                  }}
                  style={styles.followUpChip}
                >
                  {suggestion}
                </button>
              ))}
            </div>
          </>
        ) : (
          <p style={styles.userMessageText}>{message.content}</p>
        )}
      </div>

      {isUser && <div style={styles.userBadge}>👤</div>}
    </div>
  );
};

// ============================================================================
// CODE FIX BLOCK
// ============================================================================

const CodeFixBlock = ({ codeFix }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(codeFix.after);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={styles.codeFixContainer}>
      <div style={styles.codeFixLabel}>✅ Secure Fix</div>

      <div style={styles.diffContainer}>
        <div style={styles.diffHalf}>
          <div style={styles.diffLabelBefore}>❌ Before</div>
          <SyntaxHighlighter
            language="python"
            style={atomDark}
            customStyle={styles.diffCodeBefore}
            lineProps={() => ({ style: { display: 'block' } })}
          >
            {codeFix.before}
          </SyntaxHighlighter>
        </div>

        <div style={styles.diffHalf}>
          <div style={styles.diffLabelAfter}>✅ After</div>
          <SyntaxHighlighter
            language="python"
            style={atomDark}
            customStyle={styles.diffCodeAfter}
            lineProps={() => ({ style: { display: 'block' } })}
          >
            {codeFix.after}
          </SyntaxHighlighter>
        </div>
      </div>

      <div style={styles.fixExplanation}>
        <strong>Why this works:</strong> {codeFix.explanation}
      </div>

      <button onClick={handleCopy} style={styles.copyButton}>
        {copied ? '✓ Copied!' : '📋 Copy Fixed Code'}
      </button>
    </div>
  );
};

// ============================================================================
// SOURCES BLOCK
// ============================================================================

const SourcesBlock = ({ sources }) => {
  const [expanded, setExpanded] = useState({});

  return (
    <div style={styles.sourcesContainer}>
      <div style={styles.sourcesTitle}>📚 Knowledge Base</div>
      {sources.map((src, idx) => (
        <div
          key={idx}
          onClick={() => setExpanded({ ...expanded, [idx]: !expanded[idx] })}
          style={styles.sourceCard}
        >
          <div style={styles.sourceHeader}>
            <span>{src.title}</span>
            <span>{expanded[idx] ? '▼' : '▶'}</span>
          </div>
          {expanded[idx] && (
            <div style={styles.sourceSnippet}>{src.snippet}</div>
          )}
        </div>
      ))}
    </div>
  );
};

// ============================================================================
// CODE PANEL
// ============================================================================

const CodePanelContent = ({ code, language, findings, highlightedLine, onLineClick }) => {
  const lines = code.split('\n');
  const findingsByLine = {};

  findings.forEach(f => {
    const line = f.line_start || f.line || 0;
    if (!findingsByLine[line]) findingsByLine[line] = [];
    findingsByLine[line].push(f);
  });

  return (
    <div style={styles.codeContent}>
      <SyntaxHighlighter
        language={language}
        style={atomDark}
        showLineNumbers
        wrapLines
        lineProps={(lineNumber) => {
          const lineFinding = findingsByLine[lineNumber];
          return {
            style: {
              display: 'flex',
              backgroundColor: lineFinding
                ? lineFinding[0].severity === 'Critical'
                  ? 'rgba(220, 38, 38, 0.1)'
                  : lineFinding[0].severity === 'High'
                  ? 'rgba(249, 115, 22, 0.1)'
                  : 'rgba(234, 179, 8, 0.1)'
                : highlightedLine === lineNumber
                ? 'rgba(99, 102, 241, 0.1)'
                : 'transparent',
              borderLeft: lineFinding
                ? `3px solid ${getSeverityColor(lineFinding[0].severity)}`
                : 'none',
              cursor: lineFinding ? 'pointer' : 'default',
              transition: 'all 0.2s',
            },
            onClick: () => lineFinding && onLineClick(lineNumber),
          };
        }}
      >
        {code}
      </SyntaxHighlighter>
    </div>
  );
};

// ============================================================================
// TYPING INDICATOR
// ============================================================================

const TypingIndicator = () => (
  <div style={styles.typingRow}>
    <div style={styles.botBadge}>🤖</div>
    <div style={styles.messageBubble}>
      <div style={styles.typingDots}>
        <span style={{ fontSize: '13px', color: '#cbd5e1', marginRight: '8px' }}>Checking the knowledge base...</span>
        <span>●</span><span>●</span><span>●</span>
      </div>
    </div>
  </div>
);

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

const getSeverityColor = (severity) => {
  switch (severity) {
    case 'Critical': return '#dc2626';
    case 'High': return '#f97316';
    case 'Medium': return '#eab308';
    case 'Low': return '#3b82f6';
    default: return '#6b7280';
  }
};

// ============================================================================
// STYLES
// ============================================================================

const styles = {
  backdrop: {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: 'rgba(0, 0, 0, 0.5)',
    backdropFilter: 'blur(4px)',
    zIndex: 1000,
  },

  modal: {
    position: 'fixed',
    top: '50%',
    left: '50%',
    transform: 'translate(-50%, -50%) scale(1)',
    width: '90vw',
    height: '85vh',
    maxWidth: '1400px',
    maxHeight: '800px',
    backgroundColor: '#0f172a',
    border: '1px solid #334155',
    borderRadius: '12px',
    boxShadow: '0 20px 25px rgba(0, 0, 0, 0.3)',
    display: 'flex',
    flexDirection: 'column',
    zIndex: 1001,
    animation: 'modalSlideIn 0.3s ease-out',
  },

  modalHeader: {
    padding: '20px',
    borderBottom: '1px solid #334155',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
  },

  modalTitle: {
    margin: '0 0 8px 0',
    fontSize: '20px',
    fontWeight: 700,
    color: '#e2e8f0',
  },

  severityRow: {
    display: 'flex',
    gap: '8px',
    flexWrap: 'wrap',
  },

  severityTag: {
    padding: '4px 10px',
    border: '1px solid',
    borderRadius: '12px',
    fontSize: '11px',
    fontWeight: 600,
    backgroundColor: 'transparent',
  },

  headerActions: {
    display: 'flex',
    gap: '8px',
    alignItems: 'center',
  },

  toggleButton: {
    padding: '8px 12px',
    backgroundColor: 'rgba(99, 102, 241, 0.2)',
    border: '1px solid rgba(99, 102, 241, 0.4)',
    borderRadius: '6px',
    color: '#a5b4fc',
    fontSize: '12px',
    fontWeight: 600,
    cursor: 'pointer',
    transition: 'all 0.2s',
  },

  closeButton: {
    width: '32px',
    height: '32px',
    padding: 0,
    backgroundColor: 'transparent',
    border: '1px solid #334155',
    borderRadius: '6px',
    color: '#e2e8f0',
    fontSize: '18px',
    cursor: 'pointer',
    transition: 'all 0.2s',
  },

  modalBody: {
    flex: 1,
    display: 'flex',
    overflow: 'hidden',
    gap: '1px',
    backgroundColor: '#334155',
  },

  chatPanel: {
    flex: '0 0 60%',
    display: 'flex',
    flexDirection: 'column',
    backgroundColor: '#0f172a',
    overflow: 'hidden',
  },

  codePanel: {
    flex: '0 0 40%',
    display: 'flex',
    flexDirection: 'column',
    backgroundColor: '#1e293b',
    overflow: 'hidden',
    borderLeft: '1px solid #334155',
  },

  messagesContainer: {
    flex: 1,
    overflowY: 'auto',
    padding: '16px',
    display: 'flex',
    flexDirection: 'column',
    gap: '12px',
  },

  messageRow: {
    display: 'flex',
    gap: '8px',
    animation: 'slideIn 0.3s ease-out',
  },

  botBadge: {
    fontSize: '18px',
    flexShrink: 0,
  },

  userBadge: {
    fontSize: '18px',
    flexShrink: 0,
  },

  messageBubble: {
    padding: '12px 16px',
    borderRadius: '8px',
    border: '1px solid',
    wordWrap: 'break-word',
    maxWidth: '85%',
  },

  userMessageText: {
    margin: 0,
    fontSize: '14px',
    color: '#fff',
  },

  messageMarkdown: {
    fontSize: '13px',
    lineHeight: 1.5,
    color: '#cbd5e1',
  },

  typingDots: {
    display: 'flex',
    gap: '4px',
    fontSize: '12px',
  },

  codeFixContainer: {
    marginTop: '12px',
    padding: '12px',
    backgroundColor: 'rgba(16, 185, 129, 0.05)',
    border: '1px solid rgba(16, 185, 129, 0.2)',
    borderRadius: '6px',
  },

  codeFixLabel: {
    fontSize: '11px',
    fontWeight: 700,
    color: '#10b981',
    marginBottom: '8px',
    textTransform: 'uppercase',
  },

  diffContainer: {
    display: 'flex',
    gap: '8px',
    marginBottom: '12px',
  },

  diffHalf: {
    flex: 1,
  },

  diffLabelBefore: {
    fontSize: '10px',
    fontWeight: 600,
    color: '#f87171',
    marginBottom: '6px',
  },

  diffLabelAfter: {
    fontSize: '10px',
    fontWeight: 600,
    color: '#86efac',
    marginBottom: '6px',
  },

  diffCodeBefore: {
    fontSize: '11px !important',
    borderRadius: '4px !important',
    border: '1px solid #7f1d1d !important',
    maxHeight: '200px !important',
  },

  diffCodeAfter: {
    fontSize: '11px !important',
    borderRadius: '4px !important',
    border: '1px solid #166534 !important',
    maxHeight: '200px !important',
  },

  fixExplanation: {
    fontSize: '12px',
    color: '#cbd5e1',
    marginBottom: '10px',
    lineHeight: 1.4,
  },

  copyButton: {
    width: '100%',
    padding: '8px 12px',
    backgroundColor: '#10b981',
    border: 'none',
    borderRadius: '4px',
    color: '#fff',
    fontSize: '12px',
    fontWeight: 600,
    cursor: 'pointer',
    transition: 'all 0.2s',
  },

  sourcesContainer: {
    marginTop: '12px',
    padding: '12px',
    backgroundColor: 'rgba(59, 130, 246, 0.05)',
    border: '1px solid rgba(59, 130, 246, 0.2)',
    borderRadius: '6px',
  },

  sourcesTitle: {
    fontSize: '11px',
    fontWeight: 700,
    color: '#3b82f6',
    marginBottom: '8px',
    textTransform: 'uppercase',
  },

  sourceCard: {
    marginBottom: '8px',
    padding: '8px',
    backgroundColor: 'rgba(15, 23, 42, 0.5)',
    border: '1px solid #334155',
    borderRadius: '4px',
    cursor: 'pointer',
    transition: 'all 0.2s',
  },

  sourceHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    fontSize: '12px',
    fontWeight: 600,
    color: '#3b82f6',
  },

  sourceSnippet: {
    marginTop: '8px',
    fontSize: '11px',
    color: '#cbd5e1',
    lineHeight: 1.4,
    fontStyle: 'italic',
    paddingLeft: '8px',
    borderLeft: '2px solid #3b82f6',
  },

  referencedTags: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '6px',
    marginTop: '12px',
  },

  referenceTag: {
    padding: '4px 8px',
    backgroundColor: 'rgba(99, 102, 241, 0.2)',
    border: '1px solid rgba(99, 102, 241, 0.4)',
    borderRadius: '4px',
    fontSize: '11px',
    fontWeight: 600,
    color: '#a5b4fc',
    cursor: 'pointer',
    transition: 'all 0.2s',
  },

  followUpContainer: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '8px',
    marginTop: '16px',
    paddingTop: '12px',
    borderTop: '1px solid rgba(255, 255, 255, 0.1)',
  },

  followUpChip: {
    padding: '6px 12px',
    backgroundColor: 'rgba(16, 185, 129, 0.1)',
    border: '1px solid rgba(16, 185, 129, 0.3)',
    borderRadius: '16px',
    fontSize: '11px',
    color: '#34d399',
    fontWeight: 500,
    cursor: 'pointer',
    transition: 'all 0.2s ease',
    whiteSpace: 'nowrap',
  },

  inputArea: {
    padding: '12px 16px',
    borderTop: '1px solid #334155',
    display: 'flex',
    gap: '8px',
  },

  input: {
    flex: 1,
    padding: '10px 12px',
    backgroundColor: '#1e293b',
    border: '1px solid #334155',
    borderRadius: '6px',
    color: '#e2e8f0',
    fontSize: '13px',
    outline: 'none',
    transition: 'all 0.2s',
  },

  sendBtn: {
    padding: '10px 14px',
    backgroundColor: '#6366f1',
    border: 'none',
    borderRadius: '6px',
    color: '#fff',
    fontSize: '14px',
    cursor: 'pointer',
    fontWeight: 600,
    transition: 'all 0.2s',
  },

  codeContent: {
    flex: 1,
    overflowY: 'auto',
    fontSize: '12px',
  },

  typingRow: {
    display: 'flex',
    gap: '8px',
  },
};

// Add keyframe animations
const globalStyles = `
  @keyframes modalSlideIn {
    from {
      opacity: 0;
      transform: translate(-50%, -50%) scale(0.95);
    }
    to {
      opacity: 1;
      transform: translate(-50%, -50%) scale(1);
    }
  }
  
  @keyframes slideIn {
    from {
      opacity: 0;
      transform: translateY(10px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }
`;

if (typeof document !== 'undefined') {
  const styleSheet = document.createElement('style');
  styleSheet.textContent = globalStyles;
  document.head.appendChild(styleSheet);
}

export default CodeAssistantModal;
