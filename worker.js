export default {
  async fetch(request, env) {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        },
      });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // Route handlers
    if (path === '/login' && request.method === 'POST') {
      return handleLogin(request, env);
    } else if (path === '/courses' && request.method === 'POST') {
      return handleCourses(request, env);
    } else if (path === '/auto-complete' && request.method === 'POST') {
      return handleAutoComplete(request, env);
    } else {
      return jsonResponse({ error: 'Not found' }, 404);
    }
  },
};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

function generateRandomToken() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function parseCookiesFromSetCookie(setCookieHeader) {
  if (!setCookieHeader) return '';
  return setCookieHeader
    .split('\n')
    .map((c) => c.split(';')[0].trim())
    .filter((c) => c.length > 0)
    .join('; ');
}

function mergeCookies(oldCookies, newCookies) {
  const cookieMap = {};

  if (oldCookies) {
    oldCookies.split(';').forEach((cookie) => {
      const [key, value] = cookie.split('=').map((s) => s.trim());
      if (key) cookieMap[key] = value;
    });
  }

  if (newCookies) {
    newCookies.split(';').forEach((cookie) => {
      const [key, value] = cookie.split('=').map((s) => s.trim());
      if (key) cookieMap[key] = value;
    });
  }

  return Object.entries(cookieMap)
    .map(([key, value]) => `${key}=${value}`)
    .join('; ');
}

function extractValueFromHtml(html, name, attribute = 'value') {
  const regex = new RegExp(`name=["']${name}["']\\s+${attribute}=["']([^"']+)["']|${attribute}=["']([^"']+)["']\\s+name=["']${name}["']`, 'i');
  const match = html.match(regex);
  return match ? match[1] || match[2] : null;
}

function getChromeUserAgent() {
  return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
}

function buildFormUrlEncoded(data) {
  return Object.entries(data)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join('&');
}

// ============================================================================
// ENDPOINT: POST /login
// ============================================================================

async function handleLogin(request, env) {
  try {
    const { username, password } = await request.json();

    if (!username || !password) {
      return jsonResponse({ success: false, error: 'Username and password required' }, 400);
    }

    // Step 1: GET /login to extract CSRF token and get initial cookies
    const getLoginResponse = await fetch('https://pms.uaf.edu.pk/login', {
      method: 'GET',
      headers: {
        'User-Agent': getChromeUserAgent(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
      },
    });

    const getLoginHtml = await getLoginResponse.text();
    const csrfToken = extractValueFromHtml(getLoginHtml, '_token');

    if (!csrfToken) {
      return jsonResponse({ success: false, error: 'Failed to extract CSRF token' }, 500);
    }

    // Extract initial cookies from GET response
    const setCookieHeader = getLoginResponse.headers.get('set-cookie') || '';
    let cookies = parseCookiesFromSetCookie(setCookieHeader);

    // Step 2: POST login with credentials
    const loginFormData = buildFormUrlEncoded({
      _token: csrfToken,
      username: username,
      password: password,
    });

    const postLoginResponse = await fetch('https://pms.uaf.edu.pk/login', {
      method: 'POST',
      headers: {
        'User-Agent': getChromeUserAgent(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Referer': 'https://pms.uaf.edu.pk/login',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cookie': cookies,
      },
      body: loginFormData,
      redirect: 'manual',
    });

    // Check if we got redirected (success = not going back to /login)
    const redirectLocation = postLoginResponse.headers.get('location') || '';
    if (redirectLocation.includes('/login') || postLoginResponse.status === 401 || postLoginResponse.status === 422) {
      return jsonResponse({ success: false, error: 'Invalid credentials' }, 401);
    }

    // Update cookies from POST response
    const postSetCookieHeader = postLoginResponse.headers.get('set-cookie') || '';
    const newCookies = parseCookiesFromSetCookie(postSetCookieHeader);
    cookies = mergeCookies(cookies, newCookies);

    // Generate session token and store in KV
    const sessionToken = generateRandomToken();
    await env.QEC_SESSIONS.put(sessionToken, cookies, { expirationTtl: 3600 });

    return jsonResponse({ success: true, sessionToken });
  } catch (error) {
    console.error('Login error:', error);
    return jsonResponse({ success: false, error: error.message }, 500);
  }
}

// ============================================================================
// ENDPOINT: POST /courses
// ============================================================================

async function handleCourses(request, env) {
  try {
    const { sessionToken } = await request.json();

    if (!sessionToken) {
      return jsonResponse({ success: false, error: 'sessionToken required' }, 400);
    }

    // Retrieve cookies from KV
    let cookies = await env.QEC_SESSIONS.get(sessionToken);
    if (!cookies) {
      return jsonResponse({ success: false, error: 'Invalid or expired session' }, 401);
    }

    // Fetch enrolled courses page
    const coursesResponse = await fetch('https://pms.uaf.edu.pk/students/enrolled_courses', {
      method: 'GET',
      headers: {
        'User-Agent': getChromeUserAgent(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Referer': 'https://pms.uaf.edu.pk/',
        'Cookie': cookies,
      },
    });

    if (!coursesResponse.ok) {
      return jsonResponse({ success: false, error: 'Failed to fetch courses' }, 500);
    }

    const coursesHtml = await coursesResponse.text();

    // Update cookies if any new ones
    const coursesSetCookieHeader = coursesResponse.headers.get('set-cookie') || '';
    const newCookies = parseCookiesFromSetCookie(coursesSetCookieHeader);
    if (newCookies) {
      cookies = mergeCookies(cookies, newCookies);
      await env.QEC_SESSIONS.put(sessionToken, cookies, { expirationTtl: 3600 });
    }

    // Parse course cards: div.col-lg-4 containing links and status
    const courseCardRegex = /<div\s+class="[^"]*col-lg-4[^"]*"[^>]*>([\s\S]*?)<\/div>/gi;
    const cardMatches = coursesHtml.matchAll(courseCardRegex);

    const pendingCourses = [];
    let totalCourses = 0;
    let submittedCount = 0;
    let pendingCount = 0;

    for (const cardMatch of cardMatches) {
      const cardHtml = cardMatch[1];

      // Check if this is a course card (has qec_performa link)
      const hrefMatch = cardHtml.match(/href=["']([^"']*qec_performa\/\d+[^"']*)["']/);
      if (!hrefMatch) continue;

      const courseUrl = hrefMatch[1].startsWith('http') ? hrefMatch[1] : 'https://pms.uaf.edu.pk' + hrefMatch[1];
      totalCourses++;

      // Check status: look for fa-clock (pending) or fa-check (submitted)
      if (cardHtml.includes('QEC Evaluation Pending') || cardHtml.includes('fa-clock')) {
        pendingCourses.push(courseUrl);
        pendingCount++;
      } else if (cardHtml.includes('QEC Evaluation Submitted') || cardHtml.includes('fa-check')) {
        submittedCount++;
      }
    }

    // Save pending courses URLs to KV for later use
    if (pendingCourses.length > 0) {
      await env.QEC_SESSIONS.put(`${sessionToken}_urls`, JSON.stringify(pendingCourses), { expirationTtl: 3600 });
    }

    return jsonResponse({
      success: true,
      totalCourses,
      submittedCount,
      pendingCount,
      pendingCourses,
    });
  } catch (error) {
    console.error('Courses error:', error);
    return jsonResponse({ success: false, error: error.message }, 500);
  }
}

// ============================================================================
// ENDPOINT: POST /auto-complete
// ============================================================================

async function handleAutoComplete(request, env) {
  try {
    const { sessionToken, courses, selectedOption, writtenResponse } = await request.json();

    if (!sessionToken || !courses || !selectedOption || !writtenResponse) {
      return jsonResponse({ success: false, error: 'Missing required fields' }, 400);
    }

    // Validate selectedOption
    const optionMap = {
      'Strongly Agree': '4',
      'Agree': '3',
      'Somewhat Agree': '2',
      'Disagree': '1',
      'Strongly Disagree': '0',
    };

    if (!optionMap[selectedOption]) {
      return jsonResponse({ success: false, error: 'Invalid selectedOption' }, 400);
    }

    const mappedValue = optionMap[selectedOption];

    // Validate written response length
    let comments = writtenResponse;
    if (comments.length < 200) {
      comments = comments + ' ' + 'x'.repeat(200 - comments.length);
    }

    // Retrieve cookies from KV
    let cookies = await env.QEC_SESSIONS.get(sessionToken);
    if (!cookies) {
      return jsonResponse({ success: false, error: 'Invalid or expired session' }, 401);
    }

    let completed = 0;
    const total = courses.length;

    // Process each course
    for (let i = 0; i < courses.length; i++) {
      const courseUrl = courses[i];

      try {
        // GET the QEC form page
        const formPageResponse = await fetch(courseUrl, {
          method: 'GET',
          headers: {
            'User-Agent': getChromeUserAgent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://pms.uaf.edu.pk/students/enrolled_courses',
            'Cookie': cookies,
          },
        });

        if (!formPageResponse.ok) {
          console.error(`Failed to fetch form for ${courseUrl}`);
          continue;
        }

        const formHtml = await formPageResponse.text();

        // Update cookies
        const formSetCookieHeader = formPageResponse.headers.get('set-cookie') || '';
        const newCookies = parseCookiesFromSetCookie(formSetCookieHeader);
        if (newCookies) {
          cookies = mergeCookies(cookies, newCookies);
        }

        // Extract CSRF token and hidden fields
        const csrfToken = extractValueFromHtml(formHtml, '_token');
        const teacher_id = extractValueFromHtml(formHtml, 'teacher_id');
        const enroll_id = extractValueFromHtml(formHtml, 'enroll_id');
        const student_id = extractValueFromHtml(formHtml, 'student_id');
        const course_id = extractValueFromHtml(formHtml, 'course_id');
        const dpt_st_id = extractValueFromHtml(formHtml, 'dpt_st_id');

        if (!csrfToken || !teacher_id || !enroll_id || !student_id || !course_id || !dpt_st_id) {
          console.error(`Failed to extract required fields from ${courseUrl}`);
          continue;
        }

        // Build POST body
        const formData = {
          _token: csrfToken,
          teacher_id: teacher_id,
          enroll_id: enroll_id,
          student_id: student_id,
          course_id: course_id,
          dpt_st_id: dpt_st_id,
          comments: comments,
          save_submit: 'save_submit',
        };

        // Add qec_ques[] and ans_X[] for 20 questions
        for (let q = 1; q <= 20; q++) {
          formData[`qec_ques[]`] = q.toString();
          formData[`ans_${q}[]`] = mappedValue;
        }

        const postBody = buildFormUrlEncoded(formData);

        // POST submission
        const submitResponse = await fetch('https://pms.uaf.edu.pk/students/add_qec_performa_data', {
          method: 'POST',
          headers: {
            'User-Agent': getChromeUserAgent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': courseUrl,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': cookies,
          },
          body: postBody,
          redirect: 'manual',
        });

        // Success if 200 or 302
        if (submitResponse.status === 200 || submitResponse.status === 302) {
          completed++;

          // Update cookies from submission response
          const submitSetCookieHeader = submitResponse.headers.get('set-cookie') || '';
          const submitNewCookies = parseCookiesFromSetCookie(submitSetCookieHeader);
          if (submitNewCookies) {
            cookies = mergeCookies(cookies, submitNewCookies);
          }
        }
      } catch (courseError) {
        console.error(`Error processing course ${courseUrl}:`, courseError);
      }

      // Wait 700ms before next submission (except after last one)
      if (i < courses.length - 1) {
        await new Promise((resolve) => setTimeout(resolve, 700));
      }
    }

    // Update cookies in KV
    await env.QEC_SESSIONS.put(sessionToken, cookies, { expirationTtl: 3600 });

    return jsonResponse({ success: true, completed, total });
  } catch (error) {
    console.error('Auto-complete error:', error);
    return jsonResponse({ success: false, error: error.message }, 500);
  }
}
