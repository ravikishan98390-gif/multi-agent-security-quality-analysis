import React, { useState } from 'react';
import CodeAssistantModal from './CodeAssistantModal';

/**
 * CodeAssistantSection
 * 
 * Inline card component that sits below the findings/report section.
 * Provides quick-start prompts and opens the modal on interaction.
 */

const CodeAssistantSection = ({ findings, submission, jobId }) => {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [initialMessage, setInitialMessage] = useState(null);

  if (!findings || findings.length === 0) {
    return null; // Don't show if no findings
  }

  // Extract submission data
  const fileName = submission?.filename || "untitled.py";
  const language = submission?.language || "python";
  const code = submission?.code || "";

  // Count findings by severity
  const severityCounts = {
    Critical: findings.filter(f => f.severity === 'Critical').length,
    High: findings.filter(f => f.severity === 'High').length,
    Medium: findings.filter(f => f.severity === 'Medium').length,
    Low: findings.filter(f => f.severity === 'Low').length,
  };

  // Generate suggested prompts from top findings
  const generateSuggestedPrompts = () => {
    const prompts = [];
    
    // Sort by severity
    const sorted = [...findings].sort((a, b) => {
      const severityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });

    // Take top 3 unique findings
    const topFindings = sorted.slice(0, 3);

    topFindings.forEach(f => {
      if (prompts.length < 4) {
        prompts.push({
          text: `Why is the ${f.subType || f.type} on line ${f.line_start} ${f.severity.toLowerCase()}?`,
          findingId: f.id
        });
      }
      if (prompts.length < 4) {
        prompts.push({
          text: `How do I fix the ${f.subType || f.type} issue?`,
          findingId: f.id
        });
      }
    });

    return prompts.slice(0, 4);
  };

  const suggestedPrompts = generateSuggestedPrompts();

  const handleChipClick = (prompt) => {
    setInitialMessage(prompt.text);
    setIsModalOpen(true);
  };

  const handleInputSubmit = (e) => {
    e.preventDefault();
    const input = e.target.elements.assistantInput?.value?.trim();
    if (input) {
      setInitialMessage(input);
      setIsModalOpen(true);
      e.target.reset();
    }
  };

  const handleModalClose = () => {
    setIsModalOpen(false);
  };

  return (
    <>
      {/* Inline Card Section */}
      <div style={styles.sectionCard}>
        {/* Header */}
        <div style={styles.sectionHeader}>
          <div style={styles.headerTitle}>
            <span style={styles.botIcon}>🤖</span>
            <h3 style={styles.title}>Ask the Code Assistant</h3>
          </div>
          <div style={styles.severityBadgeRow}>
            {severityCounts.Critical > 0 && (
              <span style={{ ...styles.severityBadge, borderColor: '#dc2626', color: '#dc2626' }}>
                🔴 {severityCounts.Critical} Critical
              </span>
            )}
            {severityCounts.High > 0 && (
              <span style={{ ...styles.severityBadge, borderColor: '#f97316', color: '#f97316' }}>
                🟠 {severityCounts.High} High
              </span>
            )}
            {severityCounts.Medium > 0 && (
              <span style={{ ...styles.severityBadge, borderColor: '#eab308', color: '#eab308' }}>
                🟡 {severityCounts.Medium} Medium
              </span>
            )}
            {severityCounts.Low > 0 && (
              <span style={{ ...styles.severityBadge, borderColor: '#3b82f6', color: '#3b82f6' }}>
                🔵 {severityCounts.Low} Low
              </span>
            )}
          </div>
        </div>

        {/* Subtext */}
        <p style={styles.subtext}>
          Get explanations and fix suggestions for the issues found above, grounded in secure coding best practices.
        </p>

        {/* Suggested Prompts */}
        {suggestedPrompts.length > 0 && (
          <div style={styles.suggestedPromptsContainer}>
            <span style={styles.suggestedLabel}>Quick questions:</span>
            <div style={styles.chipsWrapper}>
              {suggestedPrompts.map((prompt, idx) => (
                <button
                  key={idx}
                  onClick={() => handleChipClick(prompt)}
                  style={styles.chip}
                  title={prompt.text}
                >
                  {prompt.text.substring(0, 45)}...
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Input Form */}
        <form onSubmit={handleInputSubmit} style={styles.form}>
          <input
            type="text"
            name="assistantInput"
            placeholder="Ask about any flagged issue..."
            style={styles.input}
            maxLength={120}
          />
          <button type="submit" style={styles.sendButton}>
            Send
          </button>
        </form>
      </div>

      {/* Modal - always mounted to preserve chat history */}
      <CodeAssistantModal
        isOpen={isModalOpen}
        findings={findings}
        submission={{ ...submission, code }}
        jobId={jobId}
        initialMessage={initialMessage}
        clearInitialMessage={() => setInitialMessage(null)}
        onClose={handleModalClose}
      />
    </>
  );
};

// ============================================================================
// STYLES
// ============================================================================

const styles = {
  sectionCard: {
    marginTop: '24px',
    padding: '20px',
    backgroundColor: '#1e293b',
    border: '1px solid #334155',
    borderRadius: '10px',
    boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
  },

  sectionHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: '12px',
  },

  headerTitle: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },

  botIcon: {
    fontSize: '24px',
  },

  title: {
    margin: 0,
    fontSize: '18px',
    fontWeight: 700,
    color: '#e2e8f0',
  },

  severityBadgeRow: {
    display: 'flex',
    gap: '8px',
    flexWrap: 'wrap',
    justifyContent: 'flex-end',
  },

  severityBadge: {
    padding: '4px 10px',
    borderRadius: '12px',
    border: '1px solid',
    fontSize: '11px',
    fontWeight: 600,
    backgroundColor: 'transparent',
  },

  subtext: {
    margin: '0 0 16px 0',
    fontSize: '13px',
    color: '#cbd5e1',
    lineHeight: 1.4,
  },

  suggestedPromptsContainer: {
    marginBottom: '16px',
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    flexWrap: 'wrap',
  },

  suggestedLabel: {
    fontSize: '12px',
    fontWeight: 600,
    color: '#94a3b8',
    whiteSpace: 'nowrap',
  },

  chipsWrapper: {
    display: 'flex',
    gap: '8px',
    flexWrap: 'wrap',
  },

  chip: {
    padding: '6px 12px',
    backgroundColor: 'rgba(99, 102, 241, 0.1)',
    border: '1px solid rgba(99, 102, 241, 0.3)',
    borderRadius: '16px',
    fontSize: '11px',
    color: '#a5b4fc',
    fontWeight: 500,
    cursor: 'pointer',
    transition: 'all 0.2s ease',
    whiteSpace: 'nowrap',
    maxWidth: '200px',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },

  form: {
    display: 'flex',
    gap: '8px',
  },

  input: {
    flex: 1,
    padding: '10px 14px',
    backgroundColor: '#0f172a',
    border: '1px solid #334155',
    borderRadius: '6px',
    color: '#e2e8f0',
    fontSize: '13px',
    fontFamily: 'inherit',
    outline: 'none',
    transition: 'all 0.2s ease',
  },

  sendButton: {
    padding: '10px 18px',
    backgroundColor: '#6366f1',
    border: 'none',
    borderRadius: '6px',
    color: '#fff',
    fontSize: '13px',
    fontWeight: 600,
    cursor: 'pointer',
    transition: 'all 0.2s ease',
  },
};

export default CodeAssistantSection;
