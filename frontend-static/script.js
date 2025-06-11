(function () {
  const cfg = window.APP_CONFIG || {};
  const API_BASE = cfg.API_BASE || '';
  const APP_PASS = cfg.APP_PASSWORD || 'senha';

  const loginDiv = document.getElementById('login');
  const mainDiv = document.getElementById('main');
  const loginForm = document.getElementById('login-form');
  const passwordInput = document.getElementById('password');

  const emailForm = document.getElementById('email-form');
  const emailInput = document.getElementById('email');
  const cancelBtn = document.getElementById('cancel');
  const results = document.getElementById('results');

  let jobId = null;
  let abortCtrl = null;

  loginForm.addEventListener('submit', function (e) {
    e.preventDefault();
    if (passwordInput.value === APP_PASS) {
      loginDiv.classList.add('hidden');
      mainDiv.classList.remove('hidden');
    } else {
      alert('Senha incorreta');
    }
  });

  emailForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    results.innerHTML = '';
    abortCtrl = new AbortController();
    cancelBtn.classList.remove('hidden');
    try {
      const res = await fetch(`${API_BASE}/api/port-analysis`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: emailInput.value }),
        signal: abortCtrl.signal,
      });
      const data = await res.json();
      if (data.erro) {
        alert('Erro: ' + data.erro);
        cancelBtn.classList.add('hidden');
        return;
      }
      jobId = data.job_id;
      renderPort(data.alertas || [], data.port_score || 0);
      pollSoftware(jobId);
    } catch (err) {
      if (err.name !== 'AbortError') alert('Erro ao conectar ao backend');
      cancelBtn.classList.add('hidden');
    }
  });

  cancelBtn.addEventListener('click', async function () {
    if (abortCtrl) {
      abortCtrl.abort();
      abortCtrl = null;
    }
    try { await fetch(`${API_BASE}/api/cancel-current`, { method: 'POST' }); } catch {}
    if (jobId) {
      try { await fetch(`${API_BASE}/api/cancel/${jobId}`, { method: 'POST' }); } catch {}
      jobId = null;
    }
    cancelBtn.classList.add('hidden');
    results.innerHTML = '';
  });

  async function pollSoftware(id) {
    if (!id || id !== jobId) return;
    try {
      const res = await fetch(`${API_BASE}/api/software-analysis/${id}`);
      const data = await res.json();
      if (data.alertas) {
        renderSoft(data.alertas, data.software_score || 0, data.final_score);
        cancelBtn.classList.add('hidden');
        jobId = null;
      } else {
        setTimeout(function () { pollSoftware(id); }, 2000);
      }
    } catch {
      setTimeout(function () { pollSoftware(id); }, 2000);
    }
  }

  function renderPort(alertas, score) {
    const div = document.createElement('div');
    div.className = 'result-card';
    let html = `<h3>Port Analysis</h3><p>Score: ${score}</p>`;
    if (alertas.length) {
      html += '<ul>' + alertas.map(a => `<li><strong>${a.ip}:${a.porta}</strong> → ${a.mensagem}</li>`).join('') + '</ul>';
    }
    div.innerHTML = html;
    results.appendChild(div);
  }

  function renderSoft(alertas, score, finalScore) {
    const div = document.createElement('div');
    div.className = 'result-card';
    let html = `<h3>Software Analysis</h3><p>Score: ${score}</p>`;
    if (alertas.length) {
      html += '<ul>' + alertas.map(a => `<li><strong>${a.ip}:${a.porta}</strong> → ${a.software} vulnerável a ${a.cve_id} (CVSS ${a.cvss})</li>`).join('') + '</ul>';
    }
    if (finalScore !== null && finalScore !== undefined) {
      html += `<p style="margin-top:0.5rem"><strong>Score Final: ${finalScore}</strong></p>`;
    }
    div.innerHTML = html;
    results.appendChild(div);
  }
})();
