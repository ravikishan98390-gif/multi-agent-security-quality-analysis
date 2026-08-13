/**
 * INTEGRATION EXAMPLE: CodeAssistantChat with FastAPI Backend
 * 
 * This file shows how to:
 * 1. Fetch code submission data
 * 2. Connect to the RAG assistant API
 * 3. Convert backend responses to component format
 * 4. Handle multi-turn conversations
 */

import React, { useState, useEffect } from 'react';
import CodeAssistantChat from './CodeAssistantChat';

// Enhanced version of CodeAssistantChat with backend integration
const CodeAssistantChatWithBackend = ({ jobId }) => {
  const [context, setContext] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const API_BASE = "http://127.0.0.1:5500"; // Your backend URL

  // Fetch initial data on mount
  useEffect(() => {
    const fetchInitialData = async () => {
      try {
        setLoading(true);

        // Step 1: Get job status and findings
        const statusResponse = await fetch(`${API_BASE}/api/jobs/${jobId}/status`);
        if (!statusResponse.ok) throw new Error("Failed to fetch job status");
        const statusData = await statusResponse.json();

        const findingsResponse = await fetch(`${API_BASE}/api/jobs/${jobId}/findings`);
        if (!findingsResponse.ok) throw new Error("Failed to fetch findings");
        const findingsData = await findingsResponse.json();

        // Step 2: Get submission data
        const submissionId = statusData.submission_id;
        const submissionResponse = await fetch(`${API_BASE}/api/submissions/${submissionId}`);
        if (!submissionResponse.ok) throw new Error("Failed to fetch submission");
        const submissionData = await submissionResponse.json();
        const [codeSnippet, language, filename] = submissionData;

        // Step 3: Transform findings to component format
        const transformedFindings = findingsData.map((f, idx) => ({
          id: f.id || `F${idx + 1}`,
          category: f.category || "Code Quality",
          subType: f.type || "Issue",
          severity: f.severity || "Medium",
          line: f.line_start || f.line || 0,
          description: f.description || "",
          owaspRef: f.owasp_ref || null,
          agentSource: f.agent,
          fix: f.fix || null
        }));

        // Step 4: Build context object
        setContext({
          fileName: filename || "untitled",
          language: language || "python",
          codeSnippet: codeSnippet || "",
          findings: transformedFindings,
          submissionId,
          jobId
        });

        setError(null);
      } catch (err) {
        console.error("Error fetching data:", err);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    if (jobId) {
      fetchInitialData();
    }
  }, [jobId]);

  if (loading) {
    return (
      <div style={styles.loadingContainer}>
        <div style={styles.spinner} />
        <p>Loading code review data...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div style={styles.errorContainer}>
        <p>❌ Error: {error}</p>
        <p style={styles.errorHint}>
          Make sure the backend is running on {API_BASE}
        </p>
      </div>
    );
  }

  return (
    <CodeAssistantChatWithMessaging
      initialContext={context}
      jobId={jobId}
      apiBase={API_BASE}
    />
  );
};

/**
 * Enhanced CodeAssistantChat with real backend API integration
 */
const CodeAssistantChatWithMessaging = ({ initialContext, jobId, apiBase }) => {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: buildWelcomeMessage(initialContext.findings),
      assistantData: {
        answer: buildWelcomeMessage(initialContext.findings),
        referencedFindingIds: initialContext.findings.map(f => f.id),
        codeFix: null,
        sources: []
      },
      timestamp: new Date().toISOString()
    }
  ]);
  const [inputValue, setInputValue] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [highlightedFinding, setHighlightedFinding] = useState(null);
  const messagesEndRef = React.useRef(null);

  // Auto-scroll to newest message
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  /**
   * Main message handler - connects to backend RAG assistant
   */
  const handleSendMessage = async () => {
    if (!inputValue.trim()) return;

    // Add user message
    const userMessage = {
      role: 'user',
      content: inputValue,
      timestamp: new Date().toISOString()
    };

    setMessages(prev => [...prev, userMessage]);
    const userInput = inputValue;
    setInputValue('');
    setIsLoading(true);

    try {
      // Prepare conversation history for multi-turn context
      const conversationHistory = messages
        .filter(m => m.role === 'user' || m.role === 'assistant')
        .slice(-6) // Last 6 messages for context
        .map(m => ({
          role: m.role,
          content: m.content
        }));

      // Call backend RAG assistant
      const response = await fetch(
        `${apiBase}/api/jobs/${jobId}/assistant`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            message: userInput,
            history: conversationHistory
          })
        }
      );

      if (!response.ok) {
        throw new Error(`Backend error: ${response.statusText}`);
      }

      const data = await response.json();

      // Transform backend response to component format
      const assistantMessage = {
        role: 'assistant',
        content: data.reply || data.answer || "I couldn't generate a response.",
        assistantData: {
          answer: data.reply || data.answer || "",
          referencedFindingIds: extractReferencedFindings(
            data.reply || data.answer || "",
            initialContext.findings
          ),
          codeFix: data.codeFix || null,
          sources: data.sources || []
        },
        timestamp: new Date().toISOString()
      };

      setMessages(prev => [...prev, assistantMessage]);
    } catch (error) {
      console.error("Error sending message:", error);

      const errorMessage = {
        role: 'assistant',
        content: `❌ Error: ${error.message}. Please try again.`,
        assistantData: {
          answer: `❌ Error: ${error.message}. Please try again.`,
          referencedFindingIds: [],
          codeFix: null,
          sources: []
        },
        timestamp: new Date().toISOString()
      };

      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * Handle clicking on a flagged line in code
   */
  const handleLineClick = (findingId, lineNumber) => {
    const finding = initialContext.findings.find(f => f.id === findingId);
    if (finding) {
      setHighlightedFinding(findingId);
      setInputValue(`Explain the issue on line ${lineNumber}: ${finding.subType}`);
    }
  };

  /**
   * Handle quick-select finding chips
   */
  const handleChipClick = (finding) => {
    setHighlightedFinding(finding.id);
    setInputValue(`How do I fix "${finding.subType}" on line ${finding.line}?`);
  };

  /**
   * Handle clicking on referenced findings in chat
   */
  const handleFindingTagClick = (findingId) => {
    setHighlightedFinding(findingId);
  };

  // Render the main component
  return (
    <div style={styles.container}>
      {/* Code Panel */}
      <div style={styles.codeSection}>
        <CodePanel
          context={initialContext}
          onLineClick={handleLineClick}
          highlightedFinding={highlightedFinding}
        />
      </div>

      {/* Chat Panel */}
      <div style={styles.chatSection}>
        <div style={styles.chatHeader}>
          <h2 style={styles.chatTitle}>Code Assistant</h2>
          <p style={styles.chatSubtitle}>
            {getSeverityBadges(initialContext.findings)}
          </p>
        </div>

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

        <FindingChips
          findings={initialContext.findings}
          onChipClick={handleChipClick}
        />

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
// HELPER FUNCTIONS
// ============================================================================

function buildWelcomeMessage(findings) {
  const counts = {
    Critical: findings.filter(f => f.severity === 'Critical').length,
    High: findings.filter(f => f.severity === 'High').length,
    Medium: findings.filter(f => f.severity === 'Medium').length,
    Low: findings.filter(f => f.severity === 'Low').length,
  };

  return `I found **${findings.length} issues** in your code:
- 🔴 **${counts.Critical} Critical**
- 🟠 **${counts.High} High**
- 🟡 **${counts.Medium} Medium**
- 🔵 **${counts.Low} Low**

Ask me about any issue, or click a highlighted line in the code to learn how to fix it!`;
}

function getSeverityBadges(findings) {
  const counts = {
    Critical: findings.filter(f => f.severity === 'Critical').length,
    High: findings.filter(f => f.severity === 'High').length,
    Medium: findings.filter(f => f.severity === 'Medium').length,
    Low: findings.filter(f => f.severity === 'Low').length,
  };

  return `🔴 ${counts.Critical} Critical • 🟠 ${counts.High} High • 🟡 ${counts.Medium} Medium • 🔵 ${counts.Low} Low`;
}

/**
 * Extract finding IDs mentioned in the assistant's response
 * This is a simple heuristic - your backend can return referencedFindingIds explicitly
 */
function extractReferencedFindings(answer, findings) {
  const referencedIds = [];
  
  findings.forEach(f => {
    if (answer.includes(f.subType) || answer.includes(`line ${f.line}`)) {
      referencedIds.push(f.id);
    }
  });

  return referencedIds;
}

// ============================================================================
// SUB-COMPONENTS (Simplified - import from CodeAssistantChat.jsx)
// ============================================================================

// Note: In a real app, import these from CodeAssistantChat.jsx
// For this example, here are stubs:

const CodePanel = ({ context, onLineClick, highlightedFinding }) => (
  <div>Code Panel Component (import from CodeAssistantChat.jsx)</div>
);

const FindingChips = ({ findings, onChipClick }) => (
  <div>Finding Chips Component (import from CodeAssistantChat.jsx)</div>
);

const ChatMessage = ({ message, onFindingClick }) => (
  <div>Chat Message Component (import from CodeAssistantChat.jsx)</div>
);

const TypingIndicator = () => (
  <div>Typing Indicator (import from CodeAssistantChat.jsx)</div>
);

// ============================================================================
// STYLES
// ============================================================================

const styles = {
  container: {
    display: 'flex',
    height: '100vh',
    backgroundColor: '#0f172a',
  },

  codeSection: {
    flex: '0 0 50%',
    borderRight: '1px solid #334155',
    overflow: 'hidden',
  },

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
    color: '#e2e8f0',
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
    outline: 'none',
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
  },

  loadingContainer: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    height: '100vh',
    backgroundColor: '#0f172a',
    color: '#e2e8f0',
    flexDirection: 'column',
    gap: '20px',
  },

  spinner: {
    width: '40px',
    height: '40px',
    border: '4px solid #334155',
    borderTop: '4px solid #6366f1',
    borderRadius: '50%',
    animation: 'spin 1s linear infinite',
  },

  errorContainer: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    height: '100vh',
    backgroundColor: '#0f172a',
    color: '#e2e8f0',
    flexDirection: 'column',
    gap: '20px',
    padding: '20px',
    textAlign: 'center',
  },

  errorHint: {
    fontSize: '12px',
    color: '#94a3b8',
    marginTop: '10px',
  }
};

export default CodeAssistantChatWithBackend;
