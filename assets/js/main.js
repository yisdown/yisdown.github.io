// ============================================================
// NAV — scroll effect & mobile toggle
// ============================================================

const nav = document.getElementById('main-nav');
const navToggle = document.getElementById('nav-toggle');
const mobileMenu = document.getElementById('mobile-menu');

window.addEventListener('scroll', () => {
  if (window.scrollY > 20) {
    nav.classList.add('scrolled');
  } else {
    nav.classList.remove('scrolled');
  }
}, { passive: true });

if (navToggle && mobileMenu) {
  navToggle.addEventListener('click', () => {
    mobileMenu.classList.toggle('open');
    navToggle.textContent = mobileMenu.classList.contains('open') ? '✕' : '☰';
  });
}

// ============================================================
// TABLE OF CONTENTS — auto-generate from h2/h3 in post
// ============================================================

const tocWidget = document.getElementById('toc-widget');
const tocEl = document.getElementById('toc');
const postContent = document.querySelector('.post-content');

if (tocWidget && tocEl && postContent) {
  const headings = postContent.querySelectorAll('h2, h3');

  if (headings.length >= 2) {
    tocWidget.style.display = 'block';

    const ul = document.createElement('ul');
    ul.style.cssText = 'list-style: none; padding: 0; margin: 0;';

    headings.forEach((heading, i) => {
      // Add ID if missing
      if (!heading.id) {
        heading.id = heading.textContent
          .toLowerCase()
          .replace(/[^a-z0-9\s-]/g, '')
          .replace(/\s+/g, '-');
      }

      const li = document.createElement('li');
      const isH3 = heading.tagName === 'H3';
      li.style.cssText = `margin: 0; padding: ${isH3 ? '0 0 0 0.75rem' : '0'};`;

      const a = document.createElement('a');
      a.href = `#${heading.id}`;
      a.textContent = heading.textContent;
      a.style.cssText = `
        display: block;
        font-family: 'JetBrains Mono', monospace;
        font-size: ${isH3 ? '0.72rem' : '0.78rem'};
        color: #d4d0e6;
        text-decoration: none;
        padding: 0.3rem 0.4rem;
        border-radius: 3px;
        transition: all 0.15s ease;
        line-height: 1.4;
        border-left: 2px solid transparent;
      `;

      a.addEventListener('mouseenter', () => {
        a.style.color = '#b06aff';
        a.style.background = 'rgba(176,106,255,0.07)';
      });
      a.addEventListener('mouseleave', () => {
        if (!a.classList.contains('toc-active')) {
          a.style.color = '#d4d0e6';
          a.style.background = 'transparent';
        }
      });

      li.appendChild(a);
      ul.appendChild(li);
    });

    tocEl.appendChild(ul);

    // Scroll spy
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        const id = entry.target.id;
        const link = tocEl.querySelector(`a[href="#${id}"]`);
        if (!link) return;

        if (entry.isIntersecting) {
          tocEl.querySelectorAll('a').forEach(a => {
            a.style.color = '#d4d0e6';
            a.style.background = 'transparent';
            a.style.borderLeftColor = 'transparent';
            a.classList.remove('toc-active');
          });
          link.style.color = '#b06aff';
          link.style.borderLeftColor = '#b06aff';
          link.classList.add('toc-active');
        }
      });
    }, { rootMargin: '-10% 0px -80% 0px' });

    headings.forEach(h => observer.observe(h));
  }
}

// ============================================================
// COPY CODE BUTTON — adds copy button to all code blocks
// ============================================================

document.querySelectorAll('.highlight pre, pre code').forEach(block => {
  const wrapper = block.closest('.highlight') || block.closest('pre');
  if (!wrapper || wrapper.querySelector('.copy-btn')) return;

  const btn = document.createElement('button');
  btn.textContent = 'Copy';
  btn.className = 'copy-btn';
  btn.style.cssText = `
    position: absolute;
    top: 0.5rem;
    right: 0.5rem;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #d4d0e6;
    background: rgba(74,30,138,0.3);
    border: 1px solid rgba(176,106,255,0.2);
    border-radius: 3px;
    padding: 0.2rem 0.5rem;
    cursor: pointer;
    transition: all 0.15s ease;
    z-index: 2;
  `;

  btn.addEventListener('mouseenter', () => {
    btn.style.color = '#b06aff';
    btn.style.borderColor = '#b06aff';
  });
  btn.addEventListener('mouseleave', () => {
    if (btn.textContent === 'Copy') {
      btn.style.color = '#d4d0e6';
      btn.style.borderColor = 'rgba(176,106,255,0.2)';
    }
  });

  btn.addEventListener('click', () => {
    const code = block.querySelector('code') || block;
    navigator.clipboard.writeText(code.textContent || '').then(() => {
      btn.textContent = 'Copied!';
      btn.style.color = '#39ff8a';
      btn.style.borderColor = '#39ff8a';
      setTimeout(() => {
        btn.textContent = 'Copy';
        btn.style.color = '#d4d0e6';
        btn.style.borderColor = 'rgba(176,106,255,0.2)';
      }, 2000);
    });
  });

  if (wrapper.style.position !== 'absolute') {
    wrapper.style.position = 'relative';
  }
  wrapper.appendChild(btn);
});

// ============================================================
// TERMINAL TYPING EFFECT — hero title (optional)
// ============================================================

const typingTargets = document.querySelectorAll('[data-typing]');
typingTargets.forEach(el => {
  const text = el.dataset.typing;
  el.textContent = '';
  let i = 0;
  const interval = setInterval(() => {
    el.textContent += text[i++];
    if (i >= text.length) clearInterval(interval);
  }, 60);
});

// ============================================================
// SMOOTH ANCHOR SCROLL
// ============================================================

document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', function(e) {
    const target = document.querySelector(this.getAttribute('href'));
    if (target) {
      e.preventDefault();
      const offset = 80; // nav height + buffer
      window.scrollTo({
        top: target.getBoundingClientRect().top + window.scrollY - offset,
        behavior: 'smooth'
      });
    }
  });
});
