import re

def patch():
    with open('index.html', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 1. Replace the #chatSection HTML with the new inline entry point
    old_chat_html = """      <!-- Chat Assistant -->
      <div id="chatSection" style="display:none;">
        <div class="section-title" style="margin-top:28px;">RAG Code Assistant</div>
        <div class="card">
          <div class="chat-window" id="chatWindow">
            <div class="chat-msg assistant">
              <div class="chat-avatar">AI</div>
              <div class="chat-bubble">
                Hi! I'm your secure coding assistant, grounded by OWASP guidelines.
                Ask me anything about the findings, vulnerabilities, or secure coding best practices.
              </div>
            </div>
          </div>
          <div class="chat-input-row">
            <input type="text" id="chatInput" placeholder="Ask about SQL injection, XSS, MD5 hashing…" />
            <button id="sendBtn">Send</button>
          </div>
        </div>
      </div>"""

    new_entry_html = """      <!-- Code Assistant Entry -->
      <section id="code-assistant-entry" style="display:none; margin-top:28px;">
        <div class="card" style="padding:20px; background-color:#1e293b; border-color:#334155;">
          <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:12px;">
            <div style="display:flex; align-items:center; gap:12px;">
              <span style="font-size:24px;">🤖</span>
              <h3 style="margin:0; font-size:18px; font-weight:700; color:#e2e8f0;">Ask the Code Assistant</h3>
            </div>
            <div id="ca-severity-badges" style="display:flex; gap:8px; flex-wrap:wrap; justify-content:flex-end;"></div>
          </div>
          <p style="font-size:13px; color:#cbd5e1; margin-bottom:16px;">
            Get explanations and fix suggestions for the issues found above, grounded in secure coding best practices.
          </p>
          <div style="margin-bottom:16px; display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
            <span style="font-size:12px; font-weight:600; color:#94a3b8;">Quick questions:</span>
            <div id="ca-chips" style="display:flex; gap:8px; flex-wrap:wrap;"></div>
          </div>
          <form id="ca-form" style="display:flex; gap:8px;">
            <input type="text" id="ca-input" placeholder="Ask about any flagged issue..." style="flex:1; padding:10px 14px; background:#0f172a; border:1px solid #334155; border-radius:6px; color:#e2e8f0; font-size:13px; outline:none;" />
            <button type="submit" style="padding:10px 18px; background:#6366f1; border:none; border-radius:6px; color:#fff; font-size:13px; font-weight:600; cursor:pointer;">Send</button>
          </form>
        </div>
      </section>"""
      
    if old_chat_html in content:
        content = content.replace(old_chat_html, new_entry_html)
    else:
        print("Could not find old_chat_html")
        
    # 2. Add Modal HTML before </body>
    modal_html = """
<!-- Code Assistant Modal -->
<div id="assistant-modal-backdrop" class="hidden">
  <div id="assistant-modal">
    <div class="am-header">
      <div>
        <h2 id="am-filename">untitled.py</h2>
        <div id="am-badges"></div>
      </div>
      <div class="am-actions">
        <button id="am-toggle-code" class="am-btn">↗ Show Code</button>
        <button id="am-close" class="am-btn am-close-btn">✕</button>
      </div>
    </div>
    <div class="am-body">
      <div id="am-chat-panel" class="am-chat-panel">
        <div id="am-messages" class="am-messages"></div>
        <div class="am-input-area">
          <input type="text" id="am-input" placeholder="Follow-up question..." />
          <button id="am-send">➤</button>
        </div>
      </div>
      <div id="am-code-panel" class="am-code-panel">
        <pre><code id="am-code-block"></code></pre>
      </div>
    </div>
  </div>
</div>
"""
    if "<!-- Code Assistant Modal -->" not in content:
        content = content.replace("</body>", modal_html + "\n</body>")
        
    # 3. Add CSS for modal inside <style>
    css = """
    /* ─── Assistant Modal ────────────────────────────────────────────── */
    #assistant-modal-backdrop {
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.5); backdrop-filter: blur(4px);
      z-index: 1000; display: flex; align-items: center; justify-content: center;
      opacity: 1; transition: opacity 0.2s;
    }
    #assistant-modal-backdrop.hidden {
      display: none; opacity: 0; pointer-events: none;
    }
    #assistant-modal {
      width: 90vw; height: 85vh; max-width: 1400px; max-height: 800px;
      background: #0f172a; border: 1px solid #334155; border-radius: 12px;
      box-shadow: 0 20px 25px rgba(0,0,0,0.3); display: flex; flex-direction: column;
      animation: modalSlideIn 0.3s ease-out; overflow: hidden;
    }
    .am-header {
      padding: 20px; border-bottom: 1px solid #334155;
      display: flex; justify-content: space-between; align-items: flex-start;
    }
    #am-filename { margin: 0 0 8px 0; font-size: 20px; font-weight: 700; color: #e2e8f0; }
    #am-badges { display: flex; gap: 8px; flex-wrap: wrap; }
    .am-badge {
      padding: 4px 10px; border: 1px solid; border-radius: 12px;
      font-size: 11px; font-weight: 600; background: transparent;
    }
    .am-actions { display: flex; gap: 8px; align-items: center; }
    .am-btn {
      padding: 8px 12px; background: rgba(99,102,241,0.2); border: 1px solid rgba(99,102,241,0.4);
      border-radius: 6px; color: #a5b4fc; font-size: 12px; font-weight: 600; cursor: pointer; transition: all 0.2s;
    }
    .am-btn:hover { background: rgba(99,102,241,0.3); }
    .am-close-btn { width: 32px; height: 32px; padding: 0; font-size: 18px; border-color: #334155; color: #e2e8f0; background: transparent; }
    .am-close-btn:hover { background: rgba(255,255,255,0.1); }
    .am-body { flex: 1; display: flex; overflow: hidden; gap: 1px; background: #334155; }
    
    .am-chat-panel { flex: 0 0 60%; display: flex; flex-direction: column; background: #0f172a; overflow: hidden; }
    .am-messages { flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 12px; }
    .am-input-area { padding: 12px 16px; border-top: 1px solid #334155; display: flex; gap: 8px; }
    #am-input {
      flex: 1; padding: 10px 12px; background: #1e293b; border: 1px solid #334155;
      border-radius: 6px; color: #e2e8f0; font-size: 13px; outline: none; transition: all 0.2s;
    }
    #am-send {
      padding: 10px 14px; background: #6366f1; border: none; border-radius: 6px;
      color: #fff; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.2s;
    }
    
    .am-code-panel { flex: 0 0 40%; background: #1e293b; border-left: 1px solid #334155; overflow-y: auto; font-size: 12px; font-family: 'JetBrains Mono', monospace; }
    .am-code-line { display: flex; cursor: pointer; transition: background 0.2s; padding: 0 8px; }
    .am-code-line:hover { background: rgba(99,102,241,0.1); }
    .line-num { color: #64748b; width: 30px; text-align: right; margin-right: 12px; user-select: none; }
    .line-content { white-space: pre; color: #e2e8f0; }
    .line-critical { background: rgba(220,38,38,0.1); border-left: 3px solid #dc2626; padding-left: 5px; }
    .line-high { background: rgba(249,115,22,0.1); border-left: 3px solid #f97316; padding-left: 5px; }
    .line-medium { background: rgba(234,179,8,0.1); border-left: 3px solid #eab308; padding-left: 5px; }
    
    .msg-row { display: flex; gap: 8px; animation: slideIn 0.3s ease-out; }
    .msg-user { justify-content: flex-end; }
    .msg-bot { justify-content: flex-start; }
    .msg-bubble { padding: 12px 16px; border-radius: 8px; border: 1px solid; max-width: 85%; word-wrap: break-word; font-size: 13px; line-height: 1.5; }
    .msg-user .msg-bubble { background: #6366f1; border-color: #4f46e5; color: #fff; }
    .msg-bot .msg-bubble { background: #0f172a; border-color: #334155; color: #cbd5e1; }
    .msg-icon { font-size: 18px; flex-shrink: 0; }
    
    .diff-box { margin-top: 12px; padding: 12px; background: rgba(16,185,129,0.05); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; }
    .diff-title { font-size: 11px; font-weight: 700; color: #10b981; margin-bottom: 8px; text-transform: uppercase; }
    .diff-split { display: flex; gap: 8px; margin-bottom: 12px; }
    .diff-half { flex: 1; }
    .diff-label-before { font-size: 10px; font-weight: 600; color: #f87171; margin-bottom: 6px; }
    .diff-label-after { font-size: 10px; font-weight: 600; color: #86efac; margin-bottom: 6px; }
    .diff-code { font-family: 'JetBrains Mono', monospace; font-size: 11px; padding: 8px; border-radius: 4px; overflow-x: auto; white-space: pre; }
    .diff-before { background: #1e1e1e; border: 1px solid #7f1d1d; color: #fca5a5; }
    .diff-after { background: #1e1e1e; border: 1px solid #166534; color: #bbf7d0; }
    
    .sources-box { margin-top: 12px; padding: 12px; background: rgba(59,130,246,0.05); border: 1px solid rgba(59,130,246,0.2); border-radius: 6px; }
    .sources-title { font-size: 11px; font-weight: 700; color: #3b82f6; margin-bottom: 8px; text-transform: uppercase; }
    .source-item { margin-bottom: 8px; padding: 8px; background: rgba(15,23,42,0.5); border: 1px solid #334155; border-radius: 4px; cursor: pointer; }
    .source-header { display: flex; justify-content: space-between; font-size: 12px; font-weight: 600; color: #3b82f6; }
    .source-snippet { margin-top: 8px; font-size: 11px; color: #cbd5e1; padding-left: 8px; border-left: 2px solid #3b82f6; font-style: italic; display: none; }
    .source-item.open .source-snippet { display: block; }
    
    .ca-chip {
      padding: 6px 12px; background: rgba(99,102,241,0.1); border: 1px solid rgba(99,102,241,0.3);
      border-radius: 16px; font-size: 11px; color: #a5b4fc; font-weight: 500; cursor: pointer; transition: all 0.2s ease;
      white-space: nowrap; max-width: 200px; overflow: hidden; text-overflow: ellipsis;
    }
    .ca-chip:hover { background: rgba(99,102,241,0.2); }
    
    @media (max-width: 768px) {
      .am-code-panel { display: none; flex: 1; }
      .am-code-panel.show-mobile { display: block; }
      .am-chat-panel { flex: 1; }
      .am-chat-panel.hide-mobile { display: none; }
    }
    """
    if "/* ─── Assistant Modal" not in content:
        content = content.replace("</style>", css + "\n  </style>")

    # 4. Add JS logic
    js = """
// ─── CODE ASSISTANT LOGIC ───────────────────────────────────────────────────

let modalMessages = [];
let amFindings = [];
let amCode = "";

function initAssistant(findings, filename, code) {
  amFindings = findings || [];
  amCode = code || "";
  
  // Show entry point
  document.getElementById('code-assistant-entry').style.display = 'block';
  document.getElementById('am-filename').textContent = filename || "untitled.py";
  
  // Severity counts
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  amFindings.forEach(f => { if(counts[f.severity] !== undefined) counts[f.severity]++; });
  
  const generateBadges = (cts) => {
    let html = "";
    if (cts.Critical > 0) html += `<span class="am-badge" style="border-color:#dc2626; color:#dc2626">🔴 ${cts.Critical} Critical</span>`;
    if (cts.High > 0) html += `<span class="am-badge" style="border-color:#f97316; color:#f97316">🟠 ${cts.High} High</span>`;
    if (cts.Medium > 0) html += `<span class="am-badge" style="border-color:#eab308; color:#eab308">🟡 ${cts.Medium} Medium</span>`;
    return html;
  };
  
  document.getElementById('ca-severity-badges').innerHTML = generateBadges(counts);
  document.getElementById('am-badges').innerHTML = generateBadges(counts);
  
  // Chips
  const sorted = [...amFindings].sort((a,b) => {
    const s = { Critical:0, High:1, Medium:2, Low:3 };
    return (s[a.severity]||4) - (s[b.severity]||4);
  }).slice(0,3);
  
  let chipsHtml = "";
  sorted.forEach(f => {
    chipsHtml += `<button class="ca-chip" onclick="openAssistantModal('Why is the ${f.type} on line ${f.line_start} ${f.severity.toLowerCase()}?')">Why is the ${f.type} on line ${f.line_start} ${f.severity.toLowerCase()}?</button>`;
    chipsHtml += `<button class="ca-chip" onclick="openAssistantModal('How do I fix the ${f.type} issue?')">How do I fix the ${f.type} issue?</button>`;
  });
  document.getElementById('ca-chips').innerHTML = chipsHtml;
  
  // Code render
  const codePanel = document.getElementById('am-code-block');
  const lines = amCode.split('\\n');
  let codeHtml = "";
  
  const findingsByLine = {};
  amFindings.forEach(f => {
    const l = f.line_start;
    if(!findingsByLine[l]) findingsByLine[l] = [];
    findingsByLine[l].push(f);
  });
  
  lines.forEach((line, i) => {
    const lineNum = i + 1;
    const isFlagged = findingsByLine[lineNum];
    let rowClass = "am-code-line";
    if (isFlagged) {
      const sev = isFlagged[0].severity;
      if (sev === 'Critical') rowClass += " line-critical";
      else if (sev === 'High') rowClass += " line-high";
      else if (sev === 'Medium') rowClass += " line-medium";
    }
    codeHtml += `<div class="${rowClass}" onclick="if(${!!isFlagged}) handleCodeLineClick(${lineNum})"><span class="line-num">${lineNum}</span><span class="line-content">${escapeHtml(line)}</span></div>`;
  });
  codePanel.innerHTML = codeHtml;
}

document.getElementById('ca-form')?.addEventListener('submit', (e) => {
  e.preventDefault();
  const val = document.getElementById('ca-input').value.trim();
  if (val) {
    openAssistantModal(val);
    document.getElementById('ca-input').value = "";
  }
});

function openAssistantModal(initialMsg) {
  const backdrop = document.getElementById('assistant-modal-backdrop');
  backdrop.classList.remove('hidden');
  
  if (initialMsg) {
    handleAssistantMsgSend(initialMsg);
  } else if (modalMessages.length === 0) {
    // default greet
    modalMessages.push({ role: 'assistant', data: { answer: "Hi! I'm your secure coding assistant. Ask me anything about the findings." } });
    renderModalMessages();
  }
}

function closeAssistantModal() {
  document.getElementById('assistant-modal-backdrop').classList.add('hidden');
}

document.getElementById('am-close')?.addEventListener('click', closeAssistantModal);
document.getElementById('assistant-modal-backdrop')?.addEventListener('click', (e) => {
  if (e.target.id === 'assistant-modal-backdrop') closeAssistantModal();
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeAssistantModal();
});

document.getElementById('am-toggle-code')?.addEventListener('click', (e) => {
  const codePanel = document.getElementById('am-code-panel');
  const chatPanel = document.getElementById('am-chat-panel');
  codePanel.classList.toggle('show-mobile');
  chatPanel.classList.toggle('hide-mobile');
  e.target.textContent = codePanel.classList.contains('show-mobile') ? '↙ Hide Code' : '↗ Show Code';
});

function handleCodeLineClick(lineNum) {
  const inp = document.getElementById('am-input');
  inp.value = `Explain the issue on line ${lineNum}`;
  inp.focus();
}

function handleAssistantMsgSend(msg) {
  modalMessages.push({ role: 'user', text: msg });
  renderModalMessages();
  
  // typing
  const typingId = "typing-" + Date.now();
  const typingHtml = `<div id="${typingId}" class="msg-row msg-bot"><div class="msg-icon">🤖</div><div class="msg-bubble" style="color:#cbd5e1;font-size:13px;">Checking the knowledge base... <span style="letter-spacing:2px">●●●</span></div></div>`;
  document.getElementById('am-messages').insertAdjacentHTML('beforeend', typingHtml);
  scrollToBottom();
  
  setTimeout(() => {
    document.getElementById(typingId)?.remove();
    // mock response
    modalMessages.push({
      role: 'assistant',
      data: {
        answer: "Here is an explanation of the issue you asked about. It violates **OWASP A03:2021**.",
        codeFix: {
          before: "password = 'admin'",
          after: "password = os.getenv('DB_PASS')",
          explanation: "Use environment variables to avoid hardcoded secrets."
        },
        sources: [
          { title: "OWASP Cheat Sheet", snippet: "Never hardcode passwords in the codebase." }
        ]
      }
    });
    renderModalMessages();
  }, 1000);
}

document.getElementById('am-send')?.addEventListener('click', () => {
  const inp = document.getElementById('am-input');
  if (inp.value.trim()) {
    handleAssistantMsgSend(inp.value.trim());
    inp.value = "";
  }
});
document.getElementById('am-input')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') document.getElementById('am-send').click();
});

function renderModalMessages() {
  const container = document.getElementById('am-messages');
  let html = "";
  modalMessages.forEach(m => {
    if (m.role === 'user') {
      html += `<div class="msg-row msg-user"><div class="msg-bubble">${escapeHtml(m.text)}</div><div class="msg-icon">👤</div></div>`;
    } else {
      const d = m.data;
      let text = d.answer.replace(/\\*\\*(.*?)\\*\\*/g, '<strong>$1</strong>');
      let botHtml = `<div class="msg-row msg-bot"><div class="msg-icon">🤖</div><div class="msg-bubble"><div>${text}</div>`;
      
      if (d.codeFix) {
        botHtml += `<div class="diff-box">
          <div class="diff-title">✅ Secure Fix</div>
          <div class="diff-split">
            <div class="diff-half"><div class="diff-label-before">❌ Before</div><div class="diff-code diff-before">${escapeHtml(d.codeFix.before)}</div></div>
            <div class="diff-half"><div class="diff-label-after">✅ After</div><div class="diff-code diff-after">${escapeHtml(d.codeFix.after)}</div></div>
          </div>
          <div style="font-size:12px; color:#cbd5e1;"><strong>Why:</strong> ${escapeHtml(d.codeFix.explanation)}</div>
        </div>`;
      }
      
      if (d.sources) {
        botHtml += `<div class="sources-box"><div class="sources-title">📚 Knowledge Base</div>`;
        d.sources.forEach(s => {
          botHtml += `<div class="source-item" onclick="this.classList.toggle('open')">
            <div class="source-header"><span>${escapeHtml(s.title)}</span><span>▼</span></div>
            <div class="source-snippet">${escapeHtml(s.snippet)}</div>
          </div>`;
        });
        botHtml += `</div>`;
      }
      
      botHtml += `</div></div>`;
      html += botHtml;
    }
  });
  container.innerHTML = html;
  scrollToBottom();
}

function scrollToBottom() {
  const c = document.getElementById('am-messages');
  c.scrollTop = c.scrollHeight;
}

// Hook into loadFindings
const origLoadFindings = loadFindings;
loadFindings = async function(jobId) {
  await origLoadFindings(jobId); // populate original stuff
  // now init assistant
  try {
    const res = await fetch(`${API_BASE}/api/jobs/${jobId}/findings`);
    const data = await res.json();
    
    // fetch submission to get code
    const resSub = await fetch(`${API_BASE}/api/jobs/${jobId}`);
    const jobData = await resSub.json();
    const submission = jobData.submission;
    
    initAssistant(data.findings, submission.filename, submission.code);
  } catch(e) {}
}
"""
    if "// ─── CODE ASSISTANT LOGIC" not in content:
        content = content.replace("</script>", js + "\n</script>")
        
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(content)

patch()
