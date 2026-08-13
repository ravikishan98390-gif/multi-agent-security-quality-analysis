# CodeAssistantChat - React Component Integration Guide

## Overview

`CodeAssistantChat` is a professional React chat interface for RAG-powered code review assistance. It provides:

- ✅ **Two-panel layout**: Code with highlighted findings + conversational assistant
- ✅ **Interactive code highlighting**: Click flagged lines to ask questions
- ✅ **Quick-select finding chips** for common questions
- ✅ **Code diff visualization** with before/after fixes
- ✅ **Knowledge base citations** (grounded in OWASP, secure coding standards)
- ✅ **Multi-turn conversation** with context awareness
- ✅ **Production-ready styling** with dark-mode developer aesthetic

---

## Installation

### Prerequisites

```bash
npm install react react-markdown react-syntax-highlighter prism-react-renderer
```

### Component Dependencies

```json
{
  "react": "^18.0.0",
  "react-markdown": "^9.0.0",
  "react-syntax-highlighter": "^15.5.0",
  "prism-react-renderer": "^2.1.0"
}
```

---

## Basic Usage

### 1. Import the Component

```jsx
import CodeAssistantChat from './CodeAssistantChat';

function App() {
  return <CodeAssistantChat />;
}

export default App;
```

### 2. Integrate with Your Backend

The component comes with **mock data** for demo purposes. To connect to your real backend:

#### Modify the `handleSendMessage` function in `CodeAssistantChat.jsx`:

```jsx
const handleSendMessage = async () => {
  if (!inputValue.trim()) return;

  const userMessage = {
    role: 'user',
    content: inputValue,
    timestamp: new Date().toISOString()
  };
  setMessages([...messages, userMessage]);
  setInputValue('');
  setIsLoading(true);

  try {
    // Call your backend API
    const response = await fetch(
      `http://127.0.0.1:5500/api/jobs/${jobId}/assistant`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: inputValue,
          history: messages.slice(-6).map(m => ({
            role: m.role,
            content: m.content
          }))
        })
      }
    );

    const data = await response.json();

    const assistantMessage = {
      role: 'assistant',
      content: data.answer,
      assistantData: {
        answer: data.answer,
        referencedFindingIds: data.referencedFindingIds || [],
        codeFix: data.codeFix || null,
        sources: data.sources || []
      },
      timestamp: new Date().toISOString()
    };
    
    setMessages(prev => [...prev, assistantMessage]);
  } catch (error) {
    const errorMessage = {
      role: 'assistant',
      content: `Error: ${error.message}`,
      timestamp: new Date().toISOString()
    };
    setMessages(prev => [...prev, errorMessage]);
  } finally {
    setIsLoading(false);
  }
};
```

---

## Data Model

### Context Object (Passed to Component)

The component expects findings data in this format:

```javascript
{
  fileName: "UserService.java",
  language: "python" | "java",
  codeSnippet: "string (the full source code)",
  findings: [
    {
      id: "F001",
      category: "Security Vulnerability | Code Smell | Design Anti-Pattern | ...",
      subType: "SQL Injection | God Class | Hardcoded Secret | ...",
      severity: "Critical" | "High" | "Medium" | "Low",
      line: 15,
      description: "User input concatenated into SQL query...",
      owaspRef: "A03:2021 - Injection" // optional
    }
  ]
}
```

### Assistant Response Format

Your backend should return responses in this format:

```javascript
{
  "answer": "string (markdown-formatted explanation)",
  "referencedFindingIds": ["F001", "F002"],
  "codeFix": {
    "before": "string (vulnerable code snippet)",
    "after": "string (fixed code snippet)",
    "explanation": "string (why this fix works)"
  } | null,
  "sources": [
    {
      "title": "OWASP A03:2021 - Injection",
      "snippet": "SQL injection occurs when untrusted data..."
    }
  ]
}
```

---

## Feature Details

### 1. Code Panel Highlighting

Lines are color-coded by severity:
- 🔴 **Critical**: `#dc2626` (red-600)
- 🟠 **High**: `#f97316` (orange-500)
- 🟡 **Medium**: `#eab308` (yellow-500)
- 🔵 **Low**: `#3b82f6` (blue-400)

**Clicking a highlighted line** automatically:
- Selects that finding
- Highlights it in the code
- Pre-fills the input with "Explain the issue on line X"

### 2. Finding Chips

Quick-select buttons above the input allow users to directly ask about each finding:

```
[SQL Injection - Line 15] [Hardcoded Secret - Line 4] [God Class - Line 7]
```

Clicking a chip sets the input to: `"How do I fix '[subType]' on line [X]?"`

### 3. Code Fix Renderer

When your backend returns a `codeFix` object, the component displays:

- **Side-by-side diff**: Before (red-tinted) / After (green-tinted)
- **Syntax highlighting**: Aware of Python/Java
- **Explanation**: Why the fix works
- **Copy button**: One-click copy to clipboard

### 4. Knowledge Base Citations

Sources are displayed as collapsible cards:

```
📚 Knowledge Base References
├─ OWASP A03:2021 - Injection
└─ CWE-89: SQL Injection
```

Users can expand each to read the snippet.

### 5. Multi-Turn Conversation

The component maintains conversation history and sends it with each message:

```javascript
history: [
  { role: "user", content: "What's the SQL injection?" },
  { role: "assistant", content: "..." },
  { role: "user", content: "How do I fix it?" }
]
```

This allows your backend to understand follow-up context.

---

## Customization

### Change Color Scheme

Edit the `getSeverityColor()` and `getSeverityBg()` functions:

```jsx
const getSeverityColor = (severity) => {
  switch (severity) {
    case "Critical": return "#your-color";
    // ...
  }
};
```

### Adjust Layout

The component uses flex layout. To make it responsive:

```jsx
const styles = {
  container: {
    display: 'flex',
    flexDirection: 'column', // Stack vertically on mobile
    '@media (min-width: 768px)': {
      flexDirection: 'row' // Side-by-side on desktop
    }
  }
};
```

### Customize Message Styling

Modify `styles.messageBubble`, `styles.input`, etc. to match your brand.

---

## Example: Full Integration with FastAPI Backend

```jsx
import React, { useState, useEffect } from 'react';
import CodeAssistantChat from './CodeAssistantChat';

function CodeReviewPage() {
  const [context, setContext] = useState(null);
  const [jobId, setJobId] = useState(null);

  useEffect(() => {
    // Fetch findings and submission data
    const fetchData = async () => {
      const jobResponse = await fetch('/api/jobs/job123/status');
      const jobData = await jobResponse.json();
      
      const findingsResponse = await fetch('/api/jobs/job123/findings');
      const findings = await findingsResponse.json();
      
      const submissionResponse = await fetch('/api/submissions/sub123');
      const { code, language, filename } = await submissionResponse.json();
      
      setContext({
        fileName: filename,
        language: language,
        codeSnippet: code,
        findings: findings
      });
      setJobId('job123');
    };

    fetchData();
  }, []);

  if (!context) return <div>Loading...</div>;

  return <CodeAssistantChat initialContext={context} jobId={jobId} />;
}

export default CodeReviewPage;
```

---

## Browser Support

- ✅ Chrome/Edge 90+
- ✅ Firefox 88+
- ✅ Safari 14+
- ✅ Modern mobile browsers

---

## Performance Notes

- **Auto-scroll**: Messages are streamed and the chat auto-scrolls to newest
- **Syntax highlighting**: Performed client-side using react-syntax-highlighter
- **Message limit**: Component handles 100+ messages efficiently
- **Code snippets**: Works with up to ~5000 lines of code

---

## Troubleshooting

### Messages don't appear
- Check that you're passing `assistantData` object with `answer` key
- Verify message object has `role` and `content` fields

### Code highlighting not working
- Ensure language is set to `"python"` or `"java"` (lowercase)
- Check that SyntaxHighlighter is loading (may be CSP issue)

### Responsive layout not working
- The default component uses fixed flex proportions (50% / 50%)
- Add media queries in parent container to adjust for mobile

---

## API Reference

### Props

```typescript
interface CodeAssistantChatProps {
  initialContext?: {
    fileName: string;
    language: "python" | "java";
    codeSnippet: string;
    findings: Finding[];
  };
  jobId?: string;
  onMessageSent?: (message: string) => void;
}
```

### Exported Types

```typescript
type Finding = {
  id: string;
  category: string;
  subType: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  line: number;
  description: string;
  owaspRef?: string;
};

type AssistantResponse = {
  answer: string;
  referencedFindingIds: string[];
  codeFix?: {
    before: string;
    after: string;
    explanation: string;
  };
  sources: Array<{
    title: string;
    snippet: string;
  }>;
};
```

---

## Mock Data

The component includes realistic mock data:
- **40-line Java file** (UserService.java)
- **6 findings**: 3 Critical, 2 High, 1 Medium
- **Multi-turn conversation** showing:
  - SQL injection explanation
  - Hardcoded secret remediation
  - Password hashing best practices
- **Code fix examples** with before/after diffs
- **OWASP citations** and knowledge base references

Use the mock data for testing, then replace with real data from your backend.

---

## Support & Contributing

For issues or feature requests, update the component as needed for your use case.

Key areas for customization:
1. Backend API endpoint (in `handleSendMessage`)
2. Color scheme (in `getSeverityColor`, `styles`)
3. Response rendering (add new message component types)
4. Conversation history retention (change state management)

---

**Created for: AI Code Review & Security Analysis Pipeline**
**Version: 1.0.0**
**Last Updated: 2026-08-13**
