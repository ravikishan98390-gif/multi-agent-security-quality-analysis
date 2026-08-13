import React, { useState, useEffect, useRef } from 'react';
import ReactMarkdown from 'react-markdown';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { atomDark } from 'react-syntax-highlighter/dist/esm/styles/prism';

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

/**
 * @typedef {Object} Finding
 * @property {string} id
 * @property {string} category
 * @property {string} subType
 * @property {"Critical" | "High" | "Medium" | "Low"} severity
 * @property {number} line
 * @property {string} description
 * @property {string} [owaspRef]
 */

/**
 * @typedef {Object} CodeFix
 * @property {string} before
 * @property {string} after
 * @property {string} explanation
 */

/**
 * @typedef {Object} SourceRef
 * @property {string} title
 * @property {string} snippet
 */

/**
 * @typedef {Object} AssistantResponse
 * @property {string} answer
 * @property {string[]} referencedFindingIds
 * @property {CodeFix | null} codeFix
 * @property {SourceRef[]} sources
 */

/**
 * @typedef {Object} Message
 * @property {"user" | "assistant"} role
 * @property {string} content
 * @property {AssistantResponse} [assistantData]
 * @property {string} [timestamp]
 */

// ============================================================================
// MOCK DATA
// ============================================================================

const MOCK_CONTEXT = {
  fileName: "UserService.java",
  language: "java",
  codeSnippet: `import java.sql.*;
import java.util.*;

public class UserService {
    private static final String DB_PASSWORD = "admin123"; // HARDCODED SECRET!
    private Connection connection;
    
    public UserService(Connection conn) {
        this.connection = conn;
    }
    
    // GOD CLASS - handles too many responsibilities
    public User getUserById(String userId) throws SQLException {
        // SQL INJECTION VULNERABILITY
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        
        User user = new User();
        if (rs.next()) {
            user.setId(rs.getString("id"));
            user.setUsername(rs.getString("username"));
            user.setPassword(rs.getString("password")); // PLAIN TEXT PASSWORD
            user.setEmail(rs.getString("email"));
        }
        rs.close();
        stmt.close();
        return user;
    }
    
    public void updateUser(User user) throws SQLException {
        // ANOTHER SQL INJECTION in update
        String query = "UPDATE users SET username = '" + user.getUsername() + 
                      "' WHERE id = '" + user.getId() + "'";
        Statement stmt = connection.createStatement();
        stmt.executeUpdate(query);
        stmt.close();
    }
    
    public List<User> searchUsers(String searchTerm) throws SQLException {
        // HIGH COMPLEXITY / GOD CLASS METHODS
        String query = "SELECT * FROM users WHERE username LIKE '%" + searchTerm + "%'";
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        
        List<User> users = new ArrayList<>();
        while (rs.next()) {
            User u = new User();
            u.setId(rs.getString("id"));
            u.setUsername(rs.getString("username"));
            users.add(u);
        }
        rs.close();
        stmt.close();
        return users;
    }
}`,
  findings: [
    {
      id: "F001",
      category: "Security Vulnerability",
      subType: "SQL Injection",
      severity: "Critical",
      line: 15,
      description: "User input directly concatenated into SQL query without parameterization. Attacker can inject SQL code.",
      owaspRef: "A03:2021 - Injection"
    },
    {
      id: "F002",
      category: "Security Vulnerability",
      subType: "Hardcoded Secret",
      severity: "Critical",
      line: 4,
      description: "Database password hardcoded in source code. Exposes credentials if code is leaked.",
      owaspRef: "A02:2021 - Cryptographic Failures"
    },
    {
      id: "F003",
      category: "Security Vulnerability",
      subType: "Plain Text Password Storage",
      severity: "Critical",
      line: 22,
      description: "Password stored and retrieved as plain text. Should use bcrypt/Argon2 with proper hashing.",
      owaspRef: "A02:2021 - Cryptographic Failures"
    },
    {
      id: "F004",
      category: "Code Smell",
      subType: "God Class",
      severity: "High",
      line: 7,
      description: "UserService class has too many responsibilities (user fetching, updating, searching). Violates Single Responsibility Principle.",
      owaspRef: null
    },
    {
      id: "F005",
      category: "Security Vulnerability",
      subType: "SQL Injection",
      severity: "Critical",
      line: 32,
      description: "Another SQL injection vulnerability in the searchUsers method using LIKE clause.",
      owaspRef: "A03:2021 - Injection"
    },
    {
      id: "F006",
      category: "Code Smell",
      subType: "High Complexity",
      severity: "Medium",
      line: 28,
      description: "searchUsers method has cyclomatic complexity of 8, exceeding recommended threshold of 5.",
      owaspRef: null
    }
  ]
};

// Mock conversation data showing realistic multi-turn exchanges
const MOCK_CONVERSATION = [
  {
    role: "assistant",
    content: `I found **6 issues** in your code:\n- 🔴 **3 Critical** (SQL Injection, Hardcoded Secret, Plain Text Password)\n- 🟠 **2 High** (God Class, High Complexity)\n- 🟡 **1 Medium**\n\nLet's start with the most severe: SQL injection vulnerabilities on lines 15 and 32. Click a highlighted line or choose a finding chip below to get started!`,
    assistantData: {
      answer: "I found **6 issues** in your code:\n- 🔴 **3 Critical** (SQL Injection, Hardcoded Secret, Plain Text Password)\n- 🟠 **2 High** (God Class, High Complexity)\n- 🟡 **1 Medium**\n\nLet's start with the most severe: SQL injection vulnerabilities on lines 15 and 32. Click a highlighted line or choose a finding chip below to get started!",
      referencedFindingIds: ["F001", "F002", "F003", "F004", "F005", "F006"],
      codeFix: null,
      sources: []
    },
    timestamp: new Date(Date.now() - 180000).toISOString()
  },
  {
    role: "user",
    content: "Explain the SQL injection vulnerability on line 15",
    timestamp: new Date(Date.now() - 160000).toISOString()
  },
  {
    role: "assistant",
    content: `## SQL Injection on Line 15

The vulnerability exists because user input (\`userId\`) is directly concatenated into the SQL query string without any parameterization or validation:

\`\`\`
String query = "SELECT * FROM users WHERE id = '" + userId + "'";
\`\`\`

### Why This Is Dangerous

An attacker could pass a malicious input like: \`1' OR '1'='1\`

This would transform the query to:
\`\`\`sql
SELECT * FROM users WHERE id = '1' OR '1'='1'
\`\`\`

This would return **all users** instead of just one, bypassing authorization checks.

### The Fix

Use **prepared statements** (parameterized queries) which separate SQL structure from data:`,
    assistantData: {
      answer: `## SQL Injection on Line 15

The vulnerability exists because user input (\`userId\`) is directly concatenated into the SQL query string without any parameterization or validation.

### Why This Is Dangerous

An attacker could pass malicious input like: \`1' OR '1'='1\` to extract all user data.

### The Fix

Use **prepared statements** (parameterized queries) which separate SQL structure from data.`,
      referencedFindingIds: ["F001"],
      codeFix: {
        before: `String query = "SELECT * FROM users WHERE id = '" + userId + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);`,
        after: `String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setString(1, userId);
ResultSet rs = stmt.executeQuery();`,
        explanation: "PreparedStatement automatically escapes the userId parameter, making injection impossible. The '?' placeholder is filled safely by the JDBC driver."
      },
      sources: [
        {
          title: "OWASP A03:2021 - Injection",
          snippet: "Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. Use parameterized queries for all database access."
        },
        {
          title: "CWE-89: SQL Injection",
          snippet: "SQL injection is a type of code injection that results from improper neutralization of special elements used in an SQL command."
        }
      ]
    },
    timestamp: new Date(Date.now() - 140000).toISOString()
  },
  {
    role: "user",
    content: "Should I do the same for line 32?",
    timestamp: new Date(Date.now() - 120000).toISOString()
  },
  {
    role: "assistant",
    content: `Yes, absolutely! **Line 32 has the exact same vulnerability**. The \`searchTerm\` parameter is concatenated into a LIKE clause:

\`\`\`sql
SELECT * FROM users WHERE username LIKE '%searchTerm%'
\`\`\`

Apply the same fix — use a prepared statement with placeholders:`,
    assistantData: {
      answer: "Yes, absolutely! Line 32 has the exact same vulnerability. The searchTerm parameter is concatenated into a LIKE clause. Apply the same prepared statement fix.",
      referencedFindingIds: ["F005"],
      codeFix: {
        before: `String query = "SELECT * FROM users WHERE username LIKE '%" + searchTerm + "%'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);`,
        after: `String query = "SELECT * FROM users WHERE username LIKE ?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setString(1, "%" + searchTerm + "%");
ResultSet rs = stmt.executeQuery();`,
        explanation: "The LIKE wildcards are now part of the parameter value, not the SQL structure. The JDBC driver handles all escaping automatically."
      },
      sources: [
        {
          title: "OWASP A03:2021 - Injection",
          snippet: "Always use prepared statements for dynamic SQL queries, even for LIKE clauses with wildcards."
        }
      ]
    },
    timestamp: new Date(Date.now() - 100000).toISOString()
  },
  {
    role: "user",
    content: "How do I fix the hardcoded password issue?",
    timestamp: new Date(Date.now() - 80000).toISOString()
  },
  {
    role: "assistant",
    content: `## Never Hardcode Secrets

**Rule #1 of secure coding:** Never commit passwords, API keys, or any credentials to source code — not even in comments, and definitely not in production code.

### The Fix

Load secrets from **environment variables** or a **secrets manager**:

1. **Remove** line 4 entirely
2. **Load** from environment at runtime`,
    assistantData: {
      answer: "Never hardcode passwords. Load secrets from environment variables or a secrets manager at runtime.",
      referencedFindingIds: ["F002"],
      codeFix: {
        before: `private static final String DB_PASSWORD = "admin123"; // HARDCODED SECRET!

public UserService(Connection conn) {
    this.connection = conn;
}`,
        after: `// Load from environment variable
private static final String DB_PASSWORD = System.getenv("DB_PASSWORD");

public UserService(Connection conn) {
    this.connection = conn;
    if (DB_PASSWORD == null) {
        throw new IllegalStateException("DB_PASSWORD environment variable not set");
    }
}`,
        explanation: "Environment variables are managed by the deployment platform (Docker, Kubernetes, AWS), not stored in code. This keeps secrets out of git history and source control."
      },
      sources: [
        {
          title: "OWASP A02:2021 - Cryptographic Failures",
          snippet: "Never hardcode secrets in source code. Use environment variables, secrets vaults (AWS Secrets Manager, HashiCorp Vault), or configuration servers."
        },
        {
          title: "12-Factor App Methodology",
          snippet: "Store config that varies between deploys in environment variables. This includes database credentials, API keys, and other secrets."
        }
      ]
    },
    timestamp: new Date(Date.now() - 60000).toISOString()
  }
];

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

const getSeverityColor = (severity) => {
  switch (severity) {
    case "Critical": return "#dc2626"; // red-600
    case "High": return "#f97316"; // orange-500
    case "Medium": return "#eab308"; // yellow-500
    case "Low": return "#3b82f6"; // blue-400
    default: return "#6b7280";
  }
};

const getSeverityBg = (severity) => {
  switch (severity) {
    case "Critical": return "rgba(220, 38, 38, 0.1)";
    case "High": return "rgba(249, 115, 22, 0.1)";
    case "Medium": return "rgba(234, 179, 8, 0.1)";
    case "Low": return "rgba(59, 130, 246, 0.1)";
    default: return "rgba(107, 114, 128, 0.1)";
  }
};

// ============================================================================
// COMPONENT: Code Panel with Line Highlighting
// ============================================================================

const CodePanel = ({ context, onLineClick, highlightedFinding }) => {
  const lines = context.codeSnippet.split('\n');
  const findingsByLine = {};
  
  context.findings.forEach(f => {
    if (!findingsByLine[f.line]) findingsByLine[f.line] = [];
    findingsByLine[f.line].push(f);
  });

  return (
    <div style={styles.codePanel}>
      <div style={styles.codePanelHeader}>
        <span style={styles.fileName}>{context.fileName}</span>
        <span style={styles.languageBadge}>{context.language.toUpperCase()}</span>
      </div>
      <div style={styles.codeContainer}>
        <SyntaxHighlighter
          language={context.language}
          style={atomDark}
          showLineNumbers
          lineNumberStyle={styles.lineNumber}
          customStyle={styles.syntaxHighlighter}
          wrapLines
          lineProps={(lineNumber) => {
            const findings = findingsByLine[lineNumber] || [];
            const isHighlighted = highlightedFinding && 
              findings.some(f => f.id === highlightedFinding);
            
            return {
              style: {
                display: 'flex',
                backgroundColor: findings.length > 0 
                  ? getSeverityBg(findings[0].severity)
                  : (isHighlighted ? 'rgba(99, 102, 241, 0.15)' : 'transparent'),
                borderLeft: findings.length > 0 
                  ? `3px solid ${getSeverityColor(findings[0].severity)}`
                  : (isHighlighted ? '3px solid #6366f1' : 'none'),
                cursor: findings.length > 0 ? 'pointer' : 'default',
                transition: 'all 0.2s ease',
              },
              onClick: () => findings.length > 0 && onLineClick(findings[0].id, lineNumber)
            };
          }}
        >
          {context.codeSnippet}
        </SyntaxHighlighter>
      </div>
      <div style={styles.codeLegend}>
        <div style={styles.legendItem}>
          <span style={{ ...styles.legendColor, backgroundColor: getSeverityColor("Critical") }} />
          Critical
        </div>
        <div style={styles.legendItem}>
          <span style={{ ...styles.legendColor, backgroundColor: getSeverityColor("High") }} />
          High
        </div>
        <div style={styles.legendItem}>
          <span style={{ ...styles.legendColor, backgroundColor: getSeverityColor("Medium") }} />
          Medium
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// COMPONENT: Finding Chips (Quick Select)
// ============================================================================

const FindingChips = ({ findings, onChipClick }) => {
  const uniqueFindings = {};
  findings.forEach(f => {
    if (!uniqueFindings[f.id]) uniqueFindings[f.id] = f;
  });

  return (
    <div style={styles.chipsContainer}>
      <span style={styles.chipsLabel}>Quick Actions:</span>
      <div style={styles.chipsWrapper}>
        {Object.values(uniqueFindings).map((f) => (
          <button
            key={f.id}
            onClick={() => onChipClick(f)}
            style={{
              ...styles.chip,
              backgroundColor: getSeverityBg(f.severity),
              borderColor: getSeverityColor(f.severity)
            }}
            title={f.description}
          >
            <span style={{ color: getSeverityColor(f.severity), fontWeight: 600 }}>
              {f.subType}
            </span>
            <span style={{ marginLeft: '6px', fontSize: '12px' }}>Line {f.line}</span>
          </button>
        ))}
      </div>
    </div>
  );
};

// ============================================================================
// COMPONENT: Code Fix Renderer
// ============================================================================

const CodeFixRenderer = ({ codeFix }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(codeFix.after);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={styles.codeFixContainer}>
      <div style={styles.codeFixTitle}>Code Fix</div>
      
      <div style={styles.diffContainer}>
        <div style={styles.diffHalf}>
          <div style={styles.diffLabel}>❌ Before (Vulnerable)</div>
          <SyntaxHighlighter
            language="java"
            style={atomDark}
            customStyle={{ ...styles.diffCode, backgroundColor: 'rgba(220, 38, 38, 0.1)' }}
          >
            {codeFix.before}
          </SyntaxHighlighter>
        </div>
        
        <div style={styles.diffHalf}>
          <div style={styles.diffLabel}>✅ After (Secure)</div>
          <SyntaxHighlighter
            language="java"
            style={atomDark}
            customStyle={{ ...styles.diffCode, backgroundColor: 'rgba(16, 185, 129, 0.1)' }}
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
// COMPONENT: Source Citations
// ============================================================================

const SourceCitations = ({ sources }) => {
  const [expanded, setExpanded] = useState({});

  return (
    <div style={styles.sourcesContainer}>
      <div style={styles.sourcesTitle}>📚 Knowledge Base References</div>
      {sources.map((src, idx) => (
        <div
          key={idx}
          style={styles.sourceCard}
          onClick={() => setExpanded({ ...expanded, [idx]: !expanded[idx] })}
        >
          <div style={styles.sourceHeader}>
            <span style={styles.sourceTitle}>{src.title}</span>
            <span style={styles.sourceToggle}>{expanded[idx] ? '▼' : '▶'}</span>
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
// COMPONENT: Chat Message
// ============================================================================

const ChatMessage = ({ message, onFindingClick }) => {
  const isUser = message.role === "user";
  const data = message.assistantData;

  return (
    <div style={{ ...styles.messageRow, justifyContent: isUser ? 'flex-end' : 'flex-start' }}>
      {!isUser && <div style={styles.botIcon}>🤖</div>}
      
      <div
        style={{
          ...styles.messageBubble,
          backgroundColor: isUser ? '#6366f1' : '#1f2937',
          borderColor: isUser ? '#4f46e5' : '#374151',
          maxWidth: '85%'
        }}
      >
        {data?.answer ? (
          <>
            <div style={styles.messageMarkdown}>
              <ReactMarkdown>{data.answer}</ReactMarkdown>
            </div>

            {data.codeFix && <CodeFixRenderer codeFix={data.codeFix} />}

            {data.sources && data.sources.length > 0 && (
              <SourceCitations sources={data.sources} />
            )}

            {data.referencedFindingIds && data.referencedFindingIds.length > 0 && (
              <div style={styles.referencedTags}>
                {data.referencedFindingIds.map((id) => {
                  const finding = MOCK_CONTEXT.findings.find(f => f.id === id);
                  return finding ? (
                    <button
                      key={id}
                      onClick={() => onFindingClick(id)}
                      style={{
                        ...styles.referenceTag,
                        backgroundColor: getSeverityBg(finding.severity),
                        borderColor: getSeverityColor(finding.severity)
                      }}
                    >
                      <span style={{ color: getSeverityColor(finding.severity), fontWeight: 600 }}>
                        {finding.subType}
                      </span>
                    </button>
                  ) : null;
                })}
              </div>
            )}
          </>
        ) : (
          <p style={styles.messageText}>{message.content}</p>
        )}
      </div>

      {isUser && <div style={styles.userIcon}>👤</div>}
    </div>
  );
};

// ============================================================================
// COMPONENT: Typing Indicator
// ============================================================================

const TypingIndicator = () => (
  <div style={styles.messageRow}>
    <div style={styles.botIcon}>🤖</div>
    <div style={styles.messageBubble}>
      <div style={styles.typingIndicator}>
        <span>●</span><span>●</span><span>●</span>
      </div>
    </div>
  </div>
);

// ============================================================================
// MAIN COMPONENT: CodeAssistantChat
// ============================================================================

const CodeAssistantChat = () => {
  const [messages, setMessages] = useState(MOCK_CONVERSATION);
  const [inputValue, setInputValue] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [highlightedFinding, setHighlightedFinding] = useState(null);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSendMessage = async () => {
    if (!inputValue.trim()) return;

    // Add user message
    const userMessage = {
      role: 'user',
      content: inputValue,
      timestamp: new Date().toISOString()
    };
    setMessages([...messages, userMessage]);
    setInputValue('');
    setIsLoading(true);

    // Simulate API call
    setTimeout(() => {
      const assistantMessage = {
        role: 'assistant',
        content: 'This is a demo response. In a real implementation, this would call your backend RAG API.',
        assistantData: {
          answer: '**Demo Mode**: To see full assistant responses with code fixes and citations, integrate with your backend API endpoint.',
          referencedFindingIds: [],
          codeFix: null,
          sources: [
            {
              title: 'Implementation Guide',
              snippet: 'Connect this component to your backend by updating the handleSendMessage function to call your /api/jobs/{jobId}/assistant endpoint.'
            }
          ]
        },
        timestamp: new Date().toISOString()
      };
      setMessages(prev => [...prev, assistantMessage]);
      setIsLoading(false);
    }, 1500);
  };

  const handleLineClick = (findingId, lineNumber) => {
    const finding = MOCK_CONTEXT.findings.find(f => f.id === findingId);
    if (finding) {
      setHighlightedFinding(findingId);
      setInputValue(`Explain the issue on line ${lineNumber}: ${finding.subType}`);
    }
  };

  const handleChipClick = (finding) => {
    setHighlightedFinding(finding.id);
    setInputValue(`How do I fix "${finding.subType}" on line ${finding.line}?`);
  };

  const handleFindingTagClick = (findingId) => {
    setHighlightedFinding(findingId);
  };

  // Count findings by severity
  const severityCounts = {
    Critical: MOCK_CONTEXT.findings.filter(f => f.severity === 'Critical').length,
    High: MOCK_CONTEXT.findings.filter(f => f.severity === 'High').length,
    Medium: MOCK_CONTEXT.findings.filter(f => f.severity === 'Medium').length,
    Low: MOCK_CONTEXT.findings.filter(f => f.severity === 'Low').length,
  };

  return (
    <div style={styles.container}>
      {/* LEFT PANEL: Code */}
      <div style={styles.codeSection}>
        <CodePanel
          context={MOCK_CONTEXT}
          onLineClick={handleLineClick}
          highlightedFinding={highlightedFinding}
        />
      </div>

      {/* RIGHT PANEL: Chat */}
      <div style={styles.chatSection}>
        {/* Chat Header */}
        <div style={styles.chatHeader}>
          <div>
            <h2 style={styles.chatTitle}>Code Assistant</h2>
            <p style={styles.chatSubtitle}>
              🔴 {severityCounts.Critical} Critical • 🟠 {severityCounts.High} High • 
              🟡 {severityCounts.Medium} Medium • 🔵 {severityCounts.Low} Low
            </p>
          </div>
        </div>

        {/* Chat Messages */}
        <div style={styles.messagesContainer}>
          {messages.map((msg, idx) => (
            <ChatMessage
              key={idx}
              message={msg}
              onFindingClick={handleFindingTagClick}
            />
          ))}
          {isLoading && <TypingIndicator />}
          <div ref={messagesEndRef} />
        </div>

        {/* Finding Chips */}
        <FindingChips
          findings={MOCK_CONTEXT.findings}
          onChipClick={handleChipClick}
        />

        {/* Input Area */}
        <div style={styles.inputContainer}>
          <input
            type="text"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
            placeholder="Ask about any issue... or click a highlighted line"
            style={styles.input}
            disabled={isLoading}
          />
          <button
            onClick={handleSendMessage}
            disabled={isLoading || !inputValue.trim()}
            style={styles.sendButton}
          >
            {isLoading ? '⏳' : '➤'}
          </button>
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// STYLES
// ============================================================================

const styles = {
  container: {
    display: 'flex',
    height: '100vh',
    backgroundColor: '#0f172a',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    color: '#e2e8f0',
  },

  // Code Panel
  codeSection: {
    flex: '0 0 50%',
    display: 'flex',
    flexDirection: 'column',
    borderRight: '1px solid #334155',
    overflow: 'hidden',
  },

  codePanel: {
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    backgroundColor: '#0f172a',
  },

  codePanelHeader: {
    padding: '12px 16px',
    borderBottom: '1px solid #334155',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },

  fileName: {
    fontSize: '14px',
    fontWeight: 600,
    fontFamily: '"JetBrains Mono", monospace',
  },

  languageBadge: {
    fontSize: '11px',
    padding: '4px 10px',
    backgroundColor: 'rgba(99, 102, 241, 0.2)',
    border: '1px solid rgba(99, 102, 241, 0.4)',
    borderRadius: '4px',
    fontWeight: 600,
  },

  codeContainer: {
    flex: 1,
    overflow: 'auto',
    fontSize: '13px',
  },

  syntaxHighlighter: {
    margin: '0 !important',
    padding: '16px !important',
    backgroundColor: 'transparent !important',
    fontSize: '13px !important',
  },

  lineNumber: {
    minWidth: '2.5em',
    paddingRight: '1em',
    textAlign: 'right',
    userSelect: 'none',
    color: '#64748b',
    fontFamily: '"JetBrains Mono", monospace',
  },

  codeLegend: {
    display: 'flex',
    gap: '16px',
    padding: '12px 16px',
    borderTop: '1px solid #334155',
    fontSize: '12px',
  },

  legendItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },

  legendColor: {
    width: '12px',
    height: '12px',
    borderRadius: '2px',
  },

  // Chat Section
  chatSection: {
    flex: '0 0 50%',
    display: 'flex',
    flexDirection: 'column',
    backgroundColor: '#0f172a',
  },

  chatHeader: {
    padding: '16px',
    borderBottom: '1px solid #334155',
  },

  chatTitle: {
    margin: '0 0 6px 0',
    fontSize: '18px',
    fontWeight: 700,
  },

  chatSubtitle: {
    margin: 0,
    fontSize: '12px',
    color: '#94a3b8',
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

  botIcon: {
    fontSize: '20px',
    flexShrink: 0,
  },

  userIcon: {
    fontSize: '20px',
    flexShrink: 0,
  },

  messageBubble: {
    padding: '12px 16px',
    borderRadius: '8px',
    border: '1px solid',
    wordWrap: 'break-word',
    overflowWrap: 'break-word',
  },

  messageText: {
    margin: 0,
    fontSize: '14px',
    lineHeight: 1.4,
  },

  messageMarkdown: {
    fontSize: '14px',
    lineHeight: 1.5,
  },

  typingIndicator: {
    display: 'flex',
    gap: '4px',
  },

  // Code Fix
  codeFixContainer: {
    marginTop: '12px',
    padding: '12px',
    backgroundColor: 'rgba(16, 185, 129, 0.05)',
    border: '1px solid rgba(16, 185, 129, 0.2)',
    borderRadius: '6px',
  },

  codeFixTitle: {
    fontSize: '12px',
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

  diffLabel: {
    fontSize: '11px',
    fontWeight: 600,
    marginBottom: '6px',
    color: '#cbd5e1',
  },

  diffCode: {
    fontSize: '12px !important',
    borderRadius: '4px !important',
    border: '1px solid #334155 !important',
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
    color: '#fff',
    border: 'none',
    borderRadius: '4px',
    fontSize: '12px',
    fontWeight: 600,
    cursor: 'pointer',
    transition: 'all 0.2s ease',
  },

  // Sources
  sourcesContainer: {
    marginTop: '12px',
    padding: '12px',
    backgroundColor: 'rgba(59, 130, 246, 0.05)',
    border: '1px solid rgba(59, 130, 246, 0.2)',
    borderRadius: '6px',
  },

  sourcesTitle: {
    fontSize: '12px',
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
    transition: 'all 0.2s ease',
  },

  sourceHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    fontSize: '12px',
    fontWeight: 600,
  },

  sourceTitle: {
    color: '#3b82f6',
  },

  sourceToggle: {
    color: '#64748b',
    fontSize: '10px',
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

  // Referenced Tags
  referencedTags: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '6px',
    marginTop: '12px',
  },

  referenceTag: {
    padding: '4px 8px',
    border: '1px solid',
    borderRadius: '4px',
    fontSize: '11px',
    fontWeight: 600,
    cursor: 'pointer',
    background: 'transparent',
    transition: 'all 0.2s ease',
  },

  // Chips
  chipsContainer: {
    padding: '12px 16px',
    borderTop: '1px solid #334155',
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    flexWrap: 'wrap',
  },

  chipsLabel: {
    fontSize: '12px',
    fontWeight: 600,
    color: '#94a3b8',
    flexShrink: 0,
  },

  chipsWrapper: {
    display: 'flex',
    gap: '8px',
    flexWrap: 'wrap',
  },

  chip: {
    padding: '6px 12px',
    border: '1px solid',
    borderRadius: '20px',
    fontSize: '11px',
    fontWeight: 500,
    cursor: 'pointer',
    backgroundColor: 'transparent',
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
    transition: 'all 0.2s ease',
    whiteSpace: 'nowrap',
  },

  // Input
  inputContainer: {
    padding: '12px 16px',
    borderTop: '1px solid #334155',
    display: 'flex',
    gap: '8px',
  },

  input: {
    flex: 1,
    padding: '10px 14px',
    backgroundColor: '#1e293b',
    border: '1px solid #334155',
    borderRadius: '6px',
    color: '#e2e8f0',
    fontSize: '14px',
    fontFamily: 'inherit',
    outline: 'none',
    transition: 'all 0.2s ease',
  },

  sendButton: {
    padding: '10px 16px',
    backgroundColor: '#6366f1',
    border: 'none',
    borderRadius: '6px',
    color: '#fff',
    fontSize: '16px',
    cursor: 'pointer',
    fontWeight: 600,
    transition: 'all 0.2s ease',
  },
};

export default CodeAssistantChat;
