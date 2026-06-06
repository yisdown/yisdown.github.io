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
  const headings = Array.from(postContent.querySelectorAll('h2, h3, h4'));

  if (headings.length >= 2) {
    tocWidget.style.display = 'block';

    const slugCounts = new Map();

    function slugify(text) {
      const base = text
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/-+/g, '-')
        .replace(/^-|-$/g, '') || 'section';

      const count = slugCounts.get(base) || 0;
      slugCounts.set(base, count + 1);
      return count ? `${base}-${count + 1}` : base;
    }

    function ensureId(heading) {
      if (!heading.id) {
        heading.id = slugify(heading.textContent);
      }
      return heading.id;
    }

    function createTocLink(heading, level) {
      const a = document.createElement('a');
      a.href = `#${heading.id}`;
      a.textContent = heading.textContent;
      a.className = `toc__link toc__link--level-${level}`;
      return a;
    }

    function createList(className) {
      const list = document.createElement('ul');
      list.className = className;
      return list;
    }

    const rootList = createList('toc__list toc__list--root');
    let currentH2Item = null;
    let currentH3Item = null;

    headings.forEach((heading) => {
      ensureId(heading);

      const level = Number(heading.tagName.slice(1));
      const item = document.createElement('li');
      item.className = `toc__item toc__item--level-${level}`;
      item.appendChild(createTocLink(heading, level));

      if (level === 2) {
        rootList.appendChild(item);
        currentH2Item = item;
        currentH3Item = null;
        return;
      }

      if (level === 3) {
        if (!currentH2Item) {
          rootList.appendChild(item);
          currentH3Item = item;
          return;
        }

        let childList = currentH2Item.querySelector(':scope > .toc__list');
        if (!childList) {
          childList = createList('toc__list toc__list--nested');
          currentH2Item.appendChild(childList);
        }

        childList.appendChild(item);
        currentH3Item = item;
        return;
      }

      if (level === 4) {
        const parentItem = currentH3Item || currentH2Item;
        if (!parentItem) {
          rootList.appendChild(item);
          return;
        }

        let childList = parentItem.querySelector(':scope > .toc__list');
        if (!childList) {
          childList = createList('toc__list toc__list--subnested');
          parentItem.appendChild(childList);
        }

        childList.appendChild(item);
      }
    });

    tocEl.appendChild(rootList);

    // Scroll spy
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        const id = entry.target.id;
        const link = tocEl.querySelector(`a[href="#${id}"]`);
        if (!link) return;

        if (entry.isIntersecting) {
          tocEl.querySelectorAll('a').forEach(a => {
            a.classList.remove('toc-active');
          });
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
