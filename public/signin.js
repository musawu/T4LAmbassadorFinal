async function getCurrentUser() {
  try {
    const response = await fetch('/api/me', {
      method: 'GET',
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error('Not authenticated');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching current user:', error);
    throw error;
  }
}


/**
 * Sign in user
 */

async function signIn(email, access_code, password, rememberMe = false) {
  console.log('Our credentials are...', email, access_code, password, rememberMe);
  
  try {
    const response = await fetch('/signin', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include',
      body: JSON.stringify({
        email,
        access_code: access_code,
        password,
        rememberMe
      })
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Sign in failed');
    }
    
    // ✅ Redirect to the URL provided by server
    if (data.redirect) {
      window.location.href = data.redirect;
    }
    
    return data;
  } catch (error) {
    console.error('Sign in error:', error);
    alert('Sign in failed: ' + error.message);
    throw error;
  }
}

// Add event listener when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  const form = document.getElementById('signinForm');
  
  if (form) {  // ✅ Check if form exists
    form.addEventListener('submit', async function(e) {
      e.preventDefault();
      
      const email = document.getElementById('email').value;
      const access_code = document.getElementById('access_code').value;
      const password = document.getElementById('password').value;
      const rememberMe = document.getElementById('rememberMe').checked;
      
      try {
        await signIn(email, access_code, password, rememberMe);
      } catch (error) {
        // Error already handled in signIn function
        console.error('Form submission error:', error);
      }
    });
  }
});

// Add event listener when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  const form = document.getElementById('signinForm');
  
  form.addEventListener('submit', async function(e) {
    e.preventDefault();  // Prevent default form submission
    
    const email = document.getElementById('email').value;
    const access_code = document.getElementById('access_code').value;
    const password = document.getElementById('password').value;
    const rememberMe = document.getElementById('rememberMe').checked;
    
    await signIn(email, access_code, password, rememberMe);
  });
}

);

/**
 * Sign out user
 */
async function signOut() {
  try {
    const response = await fetch('/api/logout', {
      method: 'POST',
      credentials: 'include'
    });
    
    window.location.href = '/signin';
  } catch (error) {
    console.error('Sign out error:', error);
    window.location.href = '/signin';
  }
}

// ------------------------
// USER PROFILE
// ------------------------

/**
 * Get user profile
 */
async function getUserProfile() {
  try {
    const response = await fetch('/api/profile', {
      method: 'GET',
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch profile');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching profile:', error);
    throw error;
  }
}

/**
 * Update user profile
 */
async function updateUserProfile(profileData) {
  try {
    const response = await fetch('/api/profile', {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include',
      body: JSON.stringify(profileData)
    });
    
    if (!response.ok) {
      throw new Error('Failed to update profile');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error updating profile:', error);
    throw error;
  }
}

/**
 * Update password
 */
async function updatePassword(currentPassword, newPassword) {
  try {
    const response = await fetch('/api/profile/password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include',
      body: JSON.stringify({
        currentPassword,
        newPassword
      })
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Failed to update password');
    }
    
    return data;
  } catch (error) {
    console.error('Error updating password:', error);
    throw error;
  }
}

// ------------------------
// JOURNEY PROGRESS
// ------------------------

/**
 * Get journey progress
 */
async function getJourneyProgress() {
  try {
    const response = await fetch('/api/journey', {
      method: 'GET',
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch journey progress');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching journey progress:', error);
    throw error;
  }
}

/**
 * Update task completion status
 */
async function updateTaskStatus(taskId, month, completed) {
  try {
    const response = await fetch('/api/journey/task', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include',
      body: JSON.stringify({
        taskId,
        month,
        completed
      })
    });
    
    if (!response.ok) {
      throw new Error('Failed to update task');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error updating task:', error);
    throw error;
  }
}

/**
 * Get lightweight progress stats (for polling)
 */
async function getProgressStats() {
  try {
    const response = await fetch('/api/journey/progress', {
      method: 'GET',
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch progress stats');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching progress stats:', error);
    throw error;
  }
}

/**
 * Advance to next month
 */
async function advanceToNextMonth() {
  try {
    const response = await fetch('/api/journey/advance', {
      method: 'POST',
      credentials: 'include'
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Failed to advance month');
    }
    
    return data;
  } catch (error) {
    console.error('Error advancing month:', error);
    throw error;
  }
}

/**
 * Get days remaining in program
 */
async function getDaysRemaining() {
  try {
    const response = await fetch('/api/journey/days-remaining', {
      method: 'GET',
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch days remaining');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching days remaining:', error);
    throw error;
  }
}

// ------------------------
// ARTICLES
// ------------------------

/**
 * Get all published articles
 */
async function getArticles() {
  try {
    const response = await fetch('/api/articles', {
      method: 'GET',
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch articles');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching articles:', error);
    throw error;
  }
}

/**
 * Get article by ID
 */
async function getArticleById(articleId) {
  try {
    const response = await fetch(`/api/articles/${articleId}`, {
      method: 'GET',
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch article');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching article:', error);
    throw error;
  }
}

// ------------------------
// POSTS (Community)
// ------------------------

/**
 * Get all posts
 */
async function getPosts() {
  try {
    const response = await fetch('/api/posts', {
      method: 'GET',
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch posts');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching posts:', error);
    throw error;
  }
}

/**
 * Create new post (Partner only)
 */
async function createPost(title, content, category) {
  try {
    const response = await fetch('/api/posts', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include',
      body: JSON.stringify({
        title,
        content,
        category
      })
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Failed to create post');
    }
    
    return data;
  } catch (error) {
    console.error('Error creating post:', error);
    throw error;
  }
}

// ------------------------
// DASHBOARD STATS
// ------------------------

/**
 * Get dashboard statistics
 */
async function getDashboardStats() {
  try {
    const response = await fetch('/api/dashboard/stats', {
      method: 'GET',
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch dashboard stats');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    throw error;
  }
}

// ------------------------
// NOTIFICATIONS
// ------------------------

/**
 * Get user notifications
 */
async function getNotifications() {
  try {
    const response = await fetch('/api/notifications', {
      method: 'GET',
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch notifications');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching notifications:', error);
    throw error;
  }
}

/**
 * Clear all notifications
 */
async function clearNotifications() {
  try {
    const response = await fetch('/api/notifications/clear', {
      method: 'POST',
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error('Failed to clear notifications');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error clearing notifications:', error);
    throw error;
  }
}

// ------------------------
// FILE UPLOAD
// ------------------------

/**
 * Upload CV file
 */
async function uploadCV(file) {
  try {
    const formData = new FormData();
    formData.append('cv', file);
    
    const response = await fetch('/api/upload-cv', {
      method: 'POST',
      credentials: 'include',
      body: formData
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Failed to upload CV');
    }
    
    return data;
  } catch (error) {
    console.error('Error uploading CV:', error);
    throw error;
  }
}

// ------------------------
// ADMIN FUNCTIONS
// ------------------------

/**
 * Get all ambassadors (Admin only)
 */
async function getAmbassadors(page = 1, limit = 10, status = 'all', search = '') {
  try {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString(),
      status,
      search
    });
    
    const response = await fetch(`/admin/api/ambassadors?${params}`, {
      method: 'GET',
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch ambassadors');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching ambassadors:', error);
    throw error;
  }
}

/**
 * Get ambassador by ID (Admin only)
 */
async function getAmbassadorById(ambassadorId) {
  try {
    const response = await fetch(`/admin/api/ambassadors/${ambassadorId}`, {
      method: 'GET',
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch ambassador');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching ambassador:', error);
    throw error;
  }
}

/**
 * Create new ambassador (Admin only)
 */
async function createAmbassador(name, email, access_code) {
  try {
    const response = await fetch('/admin/api/ambassadors', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include',
      body: JSON.stringify({
        name,
        email,
        access_code: access_code
      })
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Failed to create ambassador');
    }
    
    return data;
  } catch (error) {
    console.error('Error creating ambassador:', error);
    throw error;
  }
}

/**
 * Update ambassador (Admin only)
 */
async function updateAmbassador(ambassadorId, updates) {
  try {
    const response = await fetch(`/admin/api/ambassadors/${ambassadorId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include',
      body: JSON.stringify(updates)
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Failed to update ambassador');
    }
    
    return data;
  } catch (error) {
    console.error('Error updating ambassador:', error);
    throw error;
  }
}

/**
 * Delete ambassador (Admin only)
 */
async function deleteAmbassador(ambassadorId) {
  try {
    const response = await fetch(`/admin/api/ambassadors/${ambassadorId}`, {
      method: 'DELETE',
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error('Failed to delete ambassador');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error deleting ambassador:', error);
    throw error;
  }
}

/**
 * Get journey progress summary for all ambassadors (Admin only)
 */
async function getJourneyProgressSummary() {
  try {
    const response = await fetch('/admin/api/journey/summary', {
      method: 'GET',
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch journey summary');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching journey summary:', error);
    throw error;
  }
}

/**
 * Get journey progress for specific ambassador (Admin only)
 */
async function getAmbassadorJourneyProgress(ambassadorId) {
  try {
    const response = await fetch(`/admin/api/ambassadors/${ambassadorId}/journey`, {
      method: 'GET',
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch ambassador journey progress');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching ambassador journey progress:', error);
    throw error;
  }
}

/**
 * Get all partners (Admin only)
 */
async function getPartners() {
  try {
    const response = await fetch('/admin/api/partners', {
      method: 'GET',
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch partners');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching partners:', error);
    throw error;
  }
}

/**
 * Get all articles (Admin only)
 */
async function getAdminArticles(status = 'all') {
  try {
    const params = new URLSearchParams({ status });
    const response = await fetch(`/admin/api/articles?${params}`, {
      method: 'GET',
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch articles');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching articles:', error);
    throw error;
  }
}

// ------------------------
// UTILITY FUNCTIONS
// ------------------------

/**
 * Check if user is authenticated
 */
async function checkAuth() {
  try {
    const user = await getCurrentUser();
    return { authenticated: true, user };
  } catch (error) {
    return { authenticated: false, user: null };
  }
}

/**
 * Redirect to login if not authenticated
 */
async function requireAuth(redirectUrl = '/signin') {
  const { authenticated } = await checkAuth();
  if (!authenticated) {
    window.location.href = redirectUrl;
    return false;
  }
  return true;
}