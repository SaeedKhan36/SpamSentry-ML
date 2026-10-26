'use strict';

// Only the publishable key is delivered by /api/auth/config. Secrets stay in Python.
window.PostmarkAuth = (() => {
  let clerk;
  const page = document.body.dataset.authPage;

  function script(src, attributes = {}) {
    return new Promise((resolve, reject) => {
      const element = document.createElement('script');
      element.src = src;
      element.async = true;
      element.crossOrigin = 'anonymous';
      Object.entries(attributes).forEach(([key, value]) => element.setAttribute(key, value));
      element.onload = resolve;
      element.onerror = () => reject(new Error('We couldn’t load secure sign-in. Check your connection and try again.'));
      document.head.appendChild(element);
    });
  }

  function showError(message) {
    document.getElementById('auth-loading')?.setAttribute('hidden', '');
    const error = document.getElementById('auth-error');
    if (error) {
      error.hidden = false;
      error.querySelector('[data-auth-error-message]').textContent = message;
    }
  }

  async function token() {
    const value = await clerk?.session?.getToken();
    if (!value) {
      window.location.replace('/auth/login');
      throw new Error('Please sign in to continue.');
    }
    return value;
  }

  async function initialize() {
    try {
      const response = await fetch('/api/auth/config');
      if (!response.ok) throw new Error('Sign-in is temporarily unavailable. Please try again.');
      const config = await response.json();
      if (!config.configured) throw new Error('Sign-in is being set up. Please check back shortly.');
      await script(`https://${config.domain}/npm/@clerk/ui@1/dist/ui.browser.js`);
      await script(`https://${config.domain}/npm/@clerk/clerk-js@6/dist/clerk.browser.js`, {'data-clerk-publishable-key': config.publishable_key});
      clerk = window.Clerk;
      await clerk.load({
        ui: {ClerkUI: window.__internal_ClerkUICtor},
        signInUrl: '/auth/login', signUpUrl: '/auth/register',
        signInFallbackRedirectUrl: '/dashboard', signUpFallbackRedirectUrl: '/dashboard',
        afterSignOutUrl: '/',
        localization: {
          signIn: {start: {title: 'Sign in to Postmark', subtitle: 'Welcome back. A little more clarity awaits.'}},
          signUp: {start: {title: 'Create your Postmark account', subtitle: 'A private space for a more thoughtful inbox.'}}
        },
        appearance: {
          variables: {colorPrimary: '#214b3f', colorText: '#24332e', colorTextSecondary: '#6b7b62', colorBackground: '#ffffff', fontFamily: 'DM Sans, sans-serif', fontSize: '1rem', borderRadius: '0.65rem'},
          elements: {
            cardBox: {boxShadow: 'none', width: '100%', maxWidth: '100%'},
            card: {boxShadow: 'none', border: 'none', padding: '24px', width: '100%', minWidth: '0'},
            headerTitle: {fontSize: '1.6rem', lineHeight: '1.35'},
            headerSubtitle: {fontSize: '1rem', lineHeight: '1.7'},
            formFieldLabel: {fontSize: '1rem'},
            formFieldInput: {fontSize: '1rem', minHeight: '48px'},
            formButtonPrimary: {fontSize: '1rem', minHeight: '48px'},
            socialButtonsBlockButton: {fontSize: '1rem', minHeight: '48px'},
            footerActionText: {fontSize: '0.875rem'},
            footerActionLink: {fontSize: '0.875rem'},
            footer: {background: '#fafbf7'}
          }
        }
      });

      if (page === 'auth') {
        if (clerk.session?.status === 'active') { window.location.replace('/dashboard'); return false; }
        const register = location.pathname.startsWith('/auth/register');
        document.title = `${register ? 'Create an account' : 'Welcome back'} — Postmark`;
        document.getElementById('auth-loading').hidden = true;
        const mount = document.getElementById('clerk-auth');
        if (register) clerk.mountSignUp(mount, {routing: 'path', path: '/auth/register', signInUrl: '/auth/login', forceRedirectUrl: '/dashboard'});
        else clerk.mountSignIn(mount, {routing: 'path', path: '/auth/login', signUpUrl: '/auth/register', forceRedirectUrl: '/dashboard'});
        return true;
      }

      if (!clerk.session || clerk.session.status !== 'active') { window.location.replace('/auth/login'); return false; }
      const sessionToken = await token();
      const verification = await fetch('/api/me', {headers: {Authorization: `Bearer ${sessionToken}`}});
      if (!verification.ok) {
        if (verification.status === 401) { window.location.replace('/auth/login'); return false; }
        throw new Error('We couldn’t verify your session. Please try again in a moment.');
      }
      clerk.mountUserButton(document.getElementById('user-button'));
      const user = clerk.user;
      document.getElementById('profile-name').textContent = user.firstName || user.username || 'Your account';
      document.getElementById('profile-initial').textContent = (user.firstName || user.username || 'P').slice(0, 1).toUpperCase();
      document.getElementById('workspace-name').textContent = `${user.firstName || 'Your'} workspace`;
      document.getElementById('sign-out').addEventListener('click', () => clerk.signOut({redirectUrl: '/'}));
      const initialUser = user.id;
      clerk.addListener(({session, user: updatedUser}) => {
        if (!session) window.location.replace('/');
        else if (session.status !== 'active') window.location.replace('/auth/login');
        else if (updatedUser && updatedUser.id !== initialUser) window.location.replace('/dashboard');
      });
      document.body.classList.remove('dashboard-locked');
      document.getElementById('auth-loading').hidden = true;
      return true;
    } catch (error) {
      showError(error.message || 'Sign-in is temporarily unavailable. Please try again.');
      return false;
    }
  }

  return {ready: initialize(), token};
})();
