// ============================================
// SUPABASE SETUP AND CONFIGURATION
// ============================================
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const supabaseUrl =
  process.env.SUPABASE_URL || 'https://vcfsjwqxfcpzqzcjabol.supabase.co';
const supabaseKey =
  process.env.SUPABASE_ANON_KEY ||
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZjZnNqd3F4ZmNwenF6Y2phYm9sIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjE3Mzg4NDAsImV4cCI6MjA3NzMxNDg0MH0.Ulq5brZwRcaSpcJCaO2OxkCTu-VpEp8WgGsMQU3mSlo';
const supabase = createClient(supabaseUrl, supabaseKey);

// ============================================
// DATABASE HELPER FUNCTIONS
// ============================================

// Users (Ambassadors, Partners, Admins)
async function getUserByEmail(email, role = 'ambassador') {
  try {
    let table, idField;

    // Determine which table to query based on role
    if (role === 'ambassador') {
      table = 'ambassadors';
      idField = 'ambassador_id';
    } else if (role === 'partner') {
      table = 'partners';
      idField = 'partner_id';
    } else if (role === 'admin') {
      table = 'admins';
      idField = 'admin_id';
    } else {
      console.error('Invalid role:', role);
      return null;
    }

    const { data, error } = await supabase
      .from(table)
      .select('*')
      .eq('email', email.toLowerCase())
      .single();

    if (error && error.code !== 'PGRST116') {
      // PGRST116 = not found
      console.error(`Error fetching ${role}:`, error);
      return null;
    }

    // Add role to returned data for consistency
    if (data) {
      data.role = role;
      data.id = data[idField]; // Normalize ID field
    }

    return data;
  } catch (error) {
    console.error('getUserByEmail error:', error);
    return null;
  }
}

async function getUserById(id, role = 'ambassador') {
  try {
    let table, idField;

    if (role === 'ambassador') {
      table = 'ambassadors';
      idField = 'ambassador_id';
    } else if (role === 'partner') {
      table = 'partners';
      idField = 'partner_id';
    } else if (role === 'admin') {
      table = 'admins';
      idField = 'admin_id';
    } else {
      return null;
    }

    const { data, error } = await supabase
      .from(table)
      .select('*')
      .eq(idField, id)
      .single();

    if (error && error.code !== 'PGRST116') {
      console.error(`Error fetching ${role} by ID:`, error);
      return null;
    }

    if (data) {
      data.role = role;
      data.id = data[idField];
    }

    return data;
  } catch (error) {
    console.error('getUserById error:', error);
    return null;
  }
}

async function createUser(userData, role = 'ambassador') {
  try {
    let table, insertData;

    if (role === 'ambassador') {
      table = 'ambassadors';
      insertData = {
        email: userData.email.toLowerCase(),
        access_code: userData.access_code,
        first_name: userData.first_name || userData.name,
        last_name: userData.last_name || '',
        password_hash: userData.password_hash,
        salt: userData.salt,
        status: userData.status || 'active',
        whatsapp_number: userData.whatsapp_number || '',
        gender: userData.gender || '',
      };
    } else if (role === 'partner') {
      table = 'partners';
      insertData = {
        email: userData.email.toLowerCase(),
        access_code: userData.access_code,
        organization_name:
          userData.organizationName || userData.organization_name,
        contact_name: userData.contactName || userData.contact_name,
        password_hash: userData.password_hash,
        salt: userData.salt,
        status: userData.status || 'approved',
      };
    } else if (role === 'admin') {
      table = 'admins';
      insertData = {
        email: userData.email.toLowerCase(),
        access_code: userData.access_code,
        first_name: userData.first_name || userData.name,
        password_hash: userData.password_hash,
        salt: userData.salt,
        status: userData.status || 'active',
      };
    } else {
      throw new Error('Invalid role');
    }

    const { data, error } = await supabase
      .from(table)
      .insert([insertData])
      .select()
      .single();

    if (error) {
      console.error(`Error creating ${role}:`, error);
      throw error;
    }

    // Normalize ID field
    if (data) {
      data.role = role;
      if (role === 'ambassador') data.id = data.ambassador_id;
      if (role === 'partner') data.id = data.partner_id;
      if (role === 'admin') data.id = data.admin_id;
    }

    return data;
  } catch (error) {
    console.error('createUser error:', error);
    throw error;
  }
}

async function updateUser(id, updates, role = 'ambassador') {
  try {
    let table, idField;

    if (role === 'ambassador') {
      table = 'ambassadors';
      idField = 'ambassador_id';
    } else if (role === 'partner') {
      table = 'partners';
      idField = 'partner_id';
    } else if (role === 'admin') {
      table = 'admins';
      idField = 'admin_id';
    } else {
      throw new Error('Invalid role');
    }

    const { data, error } = await supabase
      .from(table)
      .update({
        ...updates,
        updated_at: new Date().toISOString(),
      })
      .eq(idField, id)
      .select()
      .single();

    if (error) {
      console.error(`Error updating ${role}:`, error);
      throw error;
    }

    if (data) {
      data.role = role;
      data.id = data[idField];
    }

    return data;
  } catch (error) {
    console.error('updateUser error:', error);
    throw error;
  }
}

async function deleteUser(id, role = 'ambassador') {
  try {
    let table, idField;

    if (role === 'ambassador') {
      table = 'ambassadors';
      idField = 'ambassador_id';
    } else if (role === 'partner') {
      table = 'partners';
      idField = 'partner_id';
    } else if (role === 'admin') {
      table = 'admins';
      idField = 'admin_id';
    } else {
      throw new Error('Invalid role');
    }

    const { error } = await supabase.from(table).delete().eq(idField, id);

    if (error) {
      console.error(`Error deleting ${role}:`, error);
      throw error;
    }

    return true;
  } catch (error) {
    console.error('deleteUser error:', error);
    throw error;
  }
}

async function listUsers(role = 'ambassador', filters = {}) {
  try {
    let table, idField;

    if (role === 'ambassador') {
      table = 'ambassadors';
      idField = 'ambassador_id';
    } else if (role === 'partner') {
      table = 'partners';
      idField = 'partner_id';
    } else if (role === 'admin') {
      table = 'admins';
      idField = 'admin_id';
    } else {
      return { items: [], total: 0 };
    }

    let query = supabase.from(table).select('*', { count: 'exact' });

    if (filters.status) {
      query = query.eq('status', filters.status);
    }

    if (filters.search) {
      const searchTerm = `%${filters.search}%`;
      query = query.or(
        `email.ilike.${searchTerm},access_code.ilike.${searchTerm},first_name.ilike.${searchTerm},contact_name.ilike.${searchTerm},organization_name.ilike.${searchTerm}`
      );
    }

    const limit = filters.limit || 20;
    const offset = filters.offset || 0;

    query = query.range(offset, offset + limit - 1);
    query = query.order('created_at', { ascending: false });

    const { data, error, count } = await query;

    if (error) {
      console.error(`Error listing ${role}s:`, error);
      return { items: [], total: 0 };
    }

    // Normalize ID fields
    const items = (data || []).map(item => ({
      ...item,
      id: item[idField],
      role: role,
    }));

    return { items, total: count || 0, limit, offset };
  } catch (error) {
    console.error('listUsers error:', error);
    return { items: [], total: 0 };
  }
}

// Journey Progress
async function getJourneyProgress(ambassadorId) {
  try {
    const { data, error } = await supabase
      .from('journey_progress')
      .select('*')
      .eq('ambassador_id', ambassadorId)
      .single();

    if (error && error.code !== 'PGRST116') {
      console.error('Error fetching journey progress:', error);
      return null;
    }

    return data;
  } catch (error) {
    console.error('getJourneyProgress error:', error);
    return null;
  }
}

async function upsertJourneyProgress(ambassadorId, progressData) {
  try {
    const { data, error } = await supabase
      .from('journey_progress')
      .upsert(
        {
          ambassador_id: ambassadorId,
          current_month: progressData.current_month,
          completed_tasks: progressData.completed_tasks || {},
          start_date: progressData.start_date,
          month_start_dates: progressData.month_start_dates || {},
          last_updated: new Date().toISOString(),
        },
        {
          onConflict: 'ambassador_id',
        }
      )
      .select()
      .single();

    if (error) {
      console.error('Error upserting journey progress:', error);
      throw error;
    }

    return data;
  } catch (error) {
    console.error('upsertJourneyProgress error:', error);
    throw error;
  }
}

async function getAllJourneyProgress() {
  try {
    const { data, error } = await supabase
      .from('journey_progress')
      .select('*')
      .order('last_updated', { ascending: false });

    if (error) {
      console.error('Error fetching all journey progress:', error);
      return [];
    }

    return data || [];
  } catch (error) {
    console.error('getAllJourneyProgress error:', error);
    return [];
  }
}

// Articles
async function getArticles(filters = {}) {
  try {
    let query = supabase.from('articles').select('*');

    if (filters.status) {
      query = query.eq('status', filters.status);
    }

    if (filters.category) {
      query = query.eq('category', filters.category);
    }

    const { data, error } = await query.order('created_at', {
      ascending: false,
    });

    if (error) {
      console.error('Error fetching articles:', error);
      return [];
    }

    return data || [];
  } catch (error) {
    console.error('getArticles error:', error);
    return [];
  }
}

async function getArticleById(id) {
  try {
    const { data, error } = await supabase
      .from('articles')
      .select('*')
      .eq('article_id', id)
      .single();

    if (error && error.code !== 'PGRST116') {
      console.error('Error fetching article:', error);
      return null;
    }

    return data;
  } catch (error) {
    console.error('getArticleById error:', error);
    return null;
  }
}

async function createArticle(articleData) {
  try {
    const { data, error } = await supabase
      .from('articles')
      .insert([
        {
          title: articleData.title,
          content: articleData.content,
          excerpt:
            articleData.excerpt || articleData.title.substring(0, 100) + '...',
          category: articleData.category || 'general',
          status: articleData.status || 'draft',
          author_id: articleData.author_id || articleData.author,
          views: 0,
          likes: 0,
        },
      ])
      .select()
      .single();

    if (error) {
      console.error('Error creating article:', error);
      throw error;
    }

    return data;
  } catch (error) {
    console.error('createArticle error:', error);
    throw error;
  }
}

async function updateArticle(id, updates) {
  try {
    const { data, error } = await supabase
      .from('articles')
      .update({
        ...updates,
        updated_at: new Date().toISOString(),
      })
      .eq('article_id', id)
      .select()
      .single();

    if (error) {
      console.error('Error updating article:', error);
      throw error;
    }

    return data;
  } catch (error) {
    console.error('updateArticle error:', error);
    throw error;
  }
}

async function deleteArticle(id) {
  try {
    const { error } = await supabase
      .from('articles')
      .delete()
      .eq('article_id', id);

    if (error) {
      console.error('Error deleting article:', error);
      throw error;
    }

    return true;
  } catch (error) {
    console.error('deleteArticle error:', error);
    throw error;
  }
}

async function incrementArticleViews(id) {
  try {
    // Get current article
    const { data: article, error: fetchError } = await supabase
      .from('articles')
      .select('views')
      .eq('article_id', id)
      .single();

    if (fetchError) {
      console.error('Error fetching article for view increment:', fetchError);
      return;
    }

    // Increment views
    const { error: updateError } = await supabase
      .from('articles')
      .update({ views: (article.views || 0) + 1 })
      .eq('article_id', id);

    if (updateError) {
      console.error('Error incrementing views:', updateError);
    }
  } catch (error) {
    console.error('incrementArticleViews error:', error);
  }
}

// Posts
async function getPosts(filters = {}) {
  try {
    let query = supabase.from('posts').select('*');

    if (filters.authorId) {
      query = query.eq('author_id', filters.authorId);
    }

    if (filters.category) {
      query = query.eq('category', filters.category);
    }

    const { data, error } = await query.order('created_at', {
      ascending: false,
    });

    if (error) {
      console.error('Error fetching posts:', error);
      return [];
    }

    return data || [];
  } catch (error) {
    console.error('getPosts error:', error);
    return [];
  }
}

async function createPost(postData) {
  try {
    const { data, error } = await supabase
      .from('posts')
      .insert([
        {
          title: postData.title,
          content: postData.content,
          category: postData.category || 'general',
          author_id: postData.author_id || postData.authorId,
          author_name:
            postData.author_name || postData.authorName || 'Anonymous',
        },
      ])
      .select()
      .single();

    if (error) {
      console.error('Error creating post:', error);
      throw error;
    }

    return data;
  } catch (error) {
    console.error('createPost error:', error);
    throw error;
  }
}

// Sessions
async function createSession(sessionData) {
  try {
    const { data, error } = await supabase
      .from('sessions')
      .insert([
        {
          session_id: sessionData.session_id,
          user_id: sessionData.user_id,
          role: sessionData.role,
          expires_at: sessionData.expires_at,
        },
      ])
      .select()
      .single();

    if (error) {
      console.error('Error creating session:', error);
      throw error;
    }

    return data;
  } catch (error) {
    console.error('createSession error:', error);
    throw error;
  }
}

async function getSession(sessionId) {
  try {
    const { data, error } = await supabase
      .from('sessions')
      .select('*')
      .eq('session_id', sessionId)
      .single();

    if (error && error.code !== 'PGRST116') {
      console.error('Error fetching session:', error);
      return null;
    }

    return data;
  } catch (error) {
    console.error('getSession error:', error);
    return null;
  }
}

async function deleteSession(sessionId) {
  try {
    const { error } = await supabase
      .from('sessions')
      .delete()
      .eq('session_id', sessionId);

    if (error) {
      console.error('Error deleting session:', error);
      return false;
    }

    return true;
  } catch (error) {
    console.error('deleteSession error:', error);
    return false;
  }
}

// ============================================
// EXPORTS
// ============================================
module.exports = {
  supabase,
  getUserByEmail,
  getUserById,
  createUser,
  updateUser,
  deleteUser,
  listUsers,
  getJourneyProgress,
  upsertJourneyProgress,
  getAllJourneyProgress,
  getArticles,
  getArticleById,
  createArticle,
  updateArticle,
  deleteArticle,
  incrementArticleViews,
  getPosts,
  createPost,
  createSession,
  getSession,
  deleteSession,
};



