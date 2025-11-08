from flask import Flask, render_template, jsonify, request, send_from_directory, session, redirect, url_for, flash
import json
import os
import re
import html
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from datetime import datetime, timedelta
import threading
import time
from functools import wraps
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import base64
import hashlib

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')  # Change this in production!
app.permanent_session_lifetime = timedelta(days=365)  # Default: 1 year, effectively permanent until logout

# Initialize URLSafeTimedSerializer for secure token generation
# Using a separate salt for conversation tokens
CONVERSATION_TOKEN_SALT = 'conversation-token-salt'
USERNAME_TOKEN_SALT = 'username-token-salt'
TOKEN_EXPIRATION_HOURS = 24  # Tokens expire after 24 hours

def get_serializer(salt):
    """Get a URLSafeTimedSerializer instance with the app's secret key"""
    return URLSafeTimedSerializer(app.secret_key, salt=salt)

def generate_conversation_token(conversation_id, username):
    """Generate a secure, time-limited token for conversation access"""
    serializer = get_serializer(CONVERSATION_TOKEN_SALT)
    # Include both conversation_id and username for validation
    data = {
        'conversation_id': conversation_id,
        'username': username,
        'timestamp': datetime.now().isoformat()
    }
    return serializer.dumps(data)

def validate_conversation_token(token, max_age_seconds=None):
    """Validate and decode a conversation token"""
    if max_age_seconds is None:
        max_age_seconds = TOKEN_EXPIRATION_HOURS * 3600  # Convert hours to seconds
    
    serializer = get_serializer(CONVERSATION_TOKEN_SALT)
    try:
        data = serializer.loads(token, max_age=max_age_seconds)
        return data
    except SignatureExpired:
        return None  # Token expired
    except BadSignature:
        return None  # Invalid token

def generate_username_token(username):
    """Generate a secure, time-limited token for username-based conversation access"""
    serializer = get_serializer(USERNAME_TOKEN_SALT)
    data = {
        'username': username,
        'timestamp': datetime.now().isoformat()
    }
    return serializer.dumps(data)

def validate_username_token(token, max_age_seconds=None):
    """Validate and decode a username token"""
    if max_age_seconds is None:
        max_age_seconds = TOKEN_EXPIRATION_HOURS * 3600  # Convert hours to seconds
    
    serializer = get_serializer(USERNAME_TOKEN_SALT)
    try:
        data = serializer.loads(token, max_age=max_age_seconds)
        return data
    except SignatureExpired:
        return None  # Token expired
    except BadSignature:
        return None  # Invalid token

# Configuration for file uploads
UPLOAD_FOLDER = 'static/images/events'
TEMP_UPLOAD_FOLDER = 'database/create'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'mp4', 'mov', 'avi', 'webm'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['TEMP_UPLOAD_FOLDER'] = TEMP_UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size (for videos)

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_temp_media():
    """Load temporary media tracking from JSON database"""
    try:
        with open('database/temp_media.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('temp_files', [])
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        return []

def save_temp_media(temp_files):
    """Save temporary media tracking to JSON database"""
    try:
        os.makedirs('database', exist_ok=True)
        with open('database/temp_media.json', 'w', encoding='utf-8') as f:
            json.dump({'temp_files': temp_files}, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error saving temp media: {e}")
        return False

def cleanup_expired_media():
    """Background task to clean up expired temporary media files"""
    while True:
        try:
            time.sleep(60)  # Check every minute
            
            temp_files = load_temp_media()
            current_time = datetime.now()
            files_to_keep = []
            
            for file_info in temp_files:
                upload_time = datetime.fromisoformat(file_info['upload_time'])
                expiry_time = upload_time + timedelta(minutes=20)
                
                if current_time >= expiry_time:
                    # Delete the file
                    file_path = file_info['file_path']
                    try:
                        if os.path.exists(file_path):
                            os.remove(file_path)
                            print(f"Deleted expired file: {file_path}")
                    except Exception as e:
                        print(f"Error deleting file {file_path}: {e}")
                else:
                    # Keep the file
                    files_to_keep.append(file_info)
            
            # Update the tracking file
            if len(files_to_keep) != len(temp_files):
                save_temp_media(files_to_keep)
                
        except Exception as e:
            print(f"Error in cleanup task: {e}")

# Start cleanup background thread
cleanup_thread = threading.Thread(target=cleanup_expired_media, daemon=True)
cleanup_thread.start()

# Add template filter for category icons
@app.template_filter('get_category_icon')
def get_category_icon_filter(category):
    """Template filter to get category icon"""
    return get_category_icon(category)

def load_posts():
    """Load posts from JSON database"""
    try:
        with open('database/posts.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('posts', [])
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        return []

def save_posts(posts):
    """Save posts to JSON database"""
    try:
        # Validate posts data
        if not isinstance(posts, list):
            print("Error: posts must be a list")
            return False
            
        # Don't save if posts list is empty (prevent data loss)
        if len(posts) == 0:
            print("Warning: Not saving empty posts list to prevent data loss")
            return False
            
        os.makedirs('database', exist_ok=True)
        with open('database/posts.json', 'w', encoding='utf-8') as f:
            json.dump({'posts': posts}, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error saving posts: {e}")
        return False

def load_notifications():
    """Load notifications from JSON database"""
    try:
        with open('database/notifications.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('notifications', [])
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        return []

def save_notifications(notifications):
    """Save notifications to JSON database"""
    try:
        # Validate notifications data
        if not isinstance(notifications, list):
            print("Error: notifications must be a list")
            return False
            
        os.makedirs('database', exist_ok=True)
        with open('database/notifications.json', 'w', encoding='utf-8') as f:
            json.dump({'notifications': notifications}, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error saving notifications: {e}")
        return False

def load_events():
    """Load events from JSON database"""
    try:
        with open('database/events.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('events', [])
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        return []

def save_events(events):
    """Save events to JSON database"""
    try:
        # Validate events data
        if not isinstance(events, list):
            print("Error: events must be a list")
            return False
            
        os.makedirs('database', exist_ok=True)
        with open('database/events.json', 'w', encoding='utf-8') as f:
            json.dump({'events': events}, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error saving events: {e}")
        return False

def get_event_categories():
    """Get unique categories from events"""
    events = load_events()
    categories = set()
    for event in events:
        if 'category' in event and event['category']:
            categories.add(event['category'])
    return sorted(list(categories))

def get_category_icon(category):
    """Get appropriate icon for category"""
    category_icons = {
        'music': 'bi-music-note',
        'sports': 'bi-trophy',
        'food': 'bi-cup-hot',
        'art': 'bi-palette',
        'tech': 'bi-laptop',
        'business': 'bi-briefcase',
        'education': 'bi-book',
        'health': 'bi-heart-pulse',
        'outdoor': 'bi-tree',
        'social': 'bi-people',
        'charity': 'bi-heart',
        'entertainment': 'bi-film',
        'travel': 'bi-geo-alt',
        'fashion': 'bi-bag',
        'photography': 'bi-camera',
        'gaming': 'bi-controller',
        'family': 'bi-house-heart',
        'friends': 'bi-people-fill',
        'work': 'bi-briefcase-fill',
        'hobby': 'bi-star'
    }
    return category_icons.get(category, 'bi-calendar-week')

def load_shop():
    """Load shop products from JSON database"""
    try:
        with open('database/shop.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('products', [])
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        return []

def save_shop(products):
    """Save shop products to JSON database"""
    try:
        # Validate products data
        if not isinstance(products, list):
            print("Error: products must be a list")
            return False
            
        os.makedirs('database', exist_ok=True)
        with open('database/shop.json', 'w', encoding='utf-8') as f:
            json.dump({'products': products}, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error saving products: {e}")
        return False

def get_shop_categories():
    """Get unique categories from shop products"""
    products = load_shop()
    categories = set()
    for product in products:
        if 'category' in product and product['category']:
            categories.add(product['category'])
    return sorted(list(categories))

def get_shop_category_icon(category):
    """Get appropriate icon for shop category"""
    category_icons = {
        'electronics': 'bi-laptop',
        'fashion': 'bi-bag',
        'home': 'bi-house',
        'sports': 'bi-trophy',
        'food': 'bi-cup-hot',
        'books': 'bi-book',
        'toys': 'bi-balloon',
        'beauty': 'bi-star',
        'automotive': 'bi-car-front',
        'garden': 'bi-flower1',
        'jewelry': 'bi-gem',
        'pets': 'bi-heart',
        'music': 'bi-music-note',
        'games': 'bi-controller',
        'office': 'bi-briefcase',
        'health': 'bi-heart-pulse'
    }
    return category_icons.get(category, 'bi-shop')

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_user_avatar():
    """Inject user avatar into all templates - ensures avatar is in session for existing sessions"""
    if 'user_id' in session and 'avatar' not in session:
        # Load user from database to get avatar
        username = session.get('username')
        if username:
            user = get_user_by_username(username)
            if user:
                session['avatar'] = user.get('avatar', 'avatar-1.jpg')
    return {}

@app.template_filter('avatar_filename')
def avatar_filename_filter(avatar_path):
    """Extract filename from avatar path, handling both full paths and filenames"""
    if not avatar_path:
        return 'avatar-1.jpg'
    # If it's already just a filename, return it
    if '/' not in avatar_path and '\\' not in avatar_path:
        return avatar_path
    # Extract filename from path (handle both / and \ separators)
    if '\\' in avatar_path:
        return avatar_path.split('\\')[-1]
    return avatar_path.split('/')[-1]

@app.before_request
def require_login():
    """Require login for all routes except login, register, logout, and static files"""
    # Allow access to login, register, logout, and static files
    if request.endpoint in ['login', 'register', 'logout']:
        return None
    
    # Allow access to static files and media
    if (request.path.startswith('/static/') or 
        request.path.startswith('/api/temp-media/') or 
        request.path.startswith('/static/images/') or
        request.path.startswith('/database/')):
        return None
    
    # Require login for all other routes
    if 'user_id' not in session:
        # Store the requested URL to redirect after login
        if request.endpoint and request.endpoint not in ['login', 'register', 'logout']:
            return redirect(url_for('login', next=request.url))
        return redirect(url_for('login'))
    
    
    return None

@app.route('/')
def home():
    # Load posts from database
    posts = load_posts()
    
    # Check if we need to highlight a specific post
    post_id = request.args.get('post')
    highlight_post_id = None
    scroll_to_post = False
    
    if post_id:
        try:
            post_id = int(post_id)
            # Verify post exists and find its index (keep posts in original order)
            for index, post in enumerate(posts):
                if post.get('id') == post_id:
                    highlight_post_id = post_id
                    scroll_to_post = True
                    break
        except (ValueError, TypeError):
            pass
    
    return render_template('index.html', 
                         posts=posts, 
                         highlight_post_id=highlight_post_id,
                         scroll_to_post=scroll_to_post)

@app.route('/post/<int:post_id>')
def view_post(post_id):
    """View a single post - backend renders only this post"""
    # Load posts from database
    posts = load_posts()
    
    # Find the specific post
    target_post = None
    for post in posts:
        if post.get('id') == post_id:
            target_post = post
            break
    
    if not target_post:
        # Post not found, redirect to home
        return redirect(url_for('home'))
    
    # Render single post view
    return render_template('post_view.html', post=target_post)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and authentication"""
    if request.method == 'POST':
        username_or_email = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember_me = request.form.get('remember_me') == 'on'
        
        if not username_or_email or not password:
            return render_template('login.html', error='Please fill in all fields')
        
        # Find user by username or email
        users = load_users()
        user = None
        
        for u in users:
            if u.get('username') == username_or_email or u.get('email') == username_or_email:
                user = u
                break
        
        if not user:
            return render_template('login.html', error='Invalid username/email or password')
        
        # Check password
        if not check_password_hash(user.get('password_hash', ''), password):
            return render_template('login.html', error='Invalid username/email or password')
        
        # Set session - make it permanent forever until logout
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['full_name'] = user.get('full_name', user['username'])
        session['avatar'] = user.get('avatar', 'avatar-1.jpg')  # Store avatar in session
        session.permanent = True
        app.permanent_session_lifetime = timedelta(days=365)  # 1 year, effectively permanent
        
        # Redirect to home or next page
        next_page = request.args.get('next')
        return redirect(next_page) if next_page else redirect(url_for('home'))
    
    # If already logged in, redirect to home
    if 'user_id' in session:
        return redirect(url_for('home'))
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page and user creation"""
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        agree_terms = request.form.get('agree_terms')
        
        # Validation
        if not all([full_name, username, email, password, confirm_password]):
            return render_template('register.html', error='Please fill in all fields')
        
        if not agree_terms:
            return render_template('register.html', error='You must agree to the terms and conditions')
        
        if len(password) < 6:
            return render_template('register.html', error='Password must be at least 6 characters')
        
        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match')
        
        # Check if username already exists
        if get_user_by_username(username):
            return render_template('register.html', error='Username already exists')
        
        # Check if email already exists
        if get_user_by_email(email):
            return render_template('register.html', error='Email already exists')
        
        # Validate username format (lowercase letters, numbers, underscore, and dot only)
        if not re.match(r'^[a-z0-9_.]+$', username):
            return render_template('register.html', error='Username can only contain lowercase letters, numbers, and these characters: _ .')
        
        # Check for uppercase letters
        if any(c.isupper() for c in username):
            return render_template('register.html', error='Username must only contain lowercase letters (no uppercase letters allowed)')
        
        if len(username) < 3 or len(username) > 30:
            return render_template('register.html', error='Username must be between 3 and 30 characters')
        
        # Create new user
        users = load_users()
        
        # Generate new user ID
        new_id = max([u.get('id', 0) for u in users], default=0) + 1
        
        # Hash password
        password_hash = generate_password_hash(password)
        
        # Get default avatar (cycle through available avatars)
        available_avatars = ['avatar-lg-1.jpg', 'avatar-lg-2.jpg', 'avatar-lg-4.jpg', 'avatar-lg-5.jpg', 
                            'avatar-1.jpg', 'avatar-2.jpg', 'avatar-3.jpg', 'avatar-4.jpg', 
                            'avatar-5.jpg', 'avatar-6.jpg', 'avatar-7.jpg']
        default_avatar = available_avatars[new_id % len(available_avatars)]
        
        new_user = {
            'id': new_id,
            'username': username,
            'full_name': full_name,
            'email': email,
            'password_hash': password_hash,
            'avatar': default_avatar,
            'cover_photo': 'profile-cover.jpg',
            'bio': '',
            'website': '',
            'location': '',
            'posts_count': 0,
            'followers_count': 0,
            'following_count': 0,
            'is_following': False,
            'is_verified': False,
            'joined_date': datetime.now().strftime('%Y-%m-%d')
        }
        
        users.append(new_user)
        
        if save_users(users):
            # Auto-login after registration - make session permanent
            session['user_id'] = new_user['id']
            session['username'] = new_user['username']
            session['full_name'] = new_user['full_name']
            session['avatar'] = new_user.get('avatar', 'avatar-1.jpg')  # Store avatar in session
            session.permanent = True
            app.permanent_session_lifetime = timedelta(days=365)  # 1 year, effectively permanent
            
            return redirect(url_for('home'))
        else:
            return render_template('register.html', error='Failed to create account. Please try again.')
    
    # If already logged in, redirect to home
    if 'user_id' in session:
        return redirect(url_for('home'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/posts')
def api_posts():
    """API endpoint to get all posts"""
    posts = load_posts()
    return jsonify(posts)

@app.route('/api/posts/create', methods=['POST'])
@login_required
def create_post():
    """Create a new post"""
    try:
        # Check if user is logged in
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Please login to create a post'}), 401
        
        # Check if image file is present
        if 'image' not in request.files:
            return jsonify({'success': False, 'error': 'No image file provided'}), 400
        
        file = request.files['image']
        caption = request.form.get('caption', '')
        
        # Validate file
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'success': False, 'error': 'Invalid file type'}), 400
        
        # Generate unique filename
        file_ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"{uuid.uuid4()}.{file_ext}"
        
        # Ensure posts directory exists
        posts_dir = os.path.join('static', 'images', 'posts')
        os.makedirs(posts_dir, exist_ok=True)
        
        # Save file
        filepath = os.path.join(posts_dir, filename)
        file.save(filepath)
        
        # Load existing posts
        posts = load_posts()
        
        # Get current user info
        current_user_id = session.get('user_id')
        current_username = session.get('username')
        current_full_name = session.get('full_name')
        
        # Get user avatar from database
        user = get_user_by_username(current_username)
        user_avatar = f"/database/avatars/{user['avatar']}" if user else '/database/avatars/avatar-1.jpg'
        
        # Generate new post ID
        new_id = max([p['id'] for p in posts], default=0) + 1
        
        # Create new post object
        from datetime import datetime
        new_post = {
            'id': new_id,
            'user_id': current_user_id,
            'username': current_username,
            'user': {
                'name': current_full_name,
                'avatar': user_avatar,
                'username': current_username
            },
            'image': f'/static/images/posts/{filename}',
            'caption': caption,
            'likes_count': 0,
            'comments_count': 0,
            'shares_count': 0,
            'time': 'Just now',
            'timestamp': datetime.now().isoformat(),
            'is_liked': False,
            'is_saved': False,
            'allow_comments': request.form.get('allow_comments', 'on') == 'on',
            'show_like_count': request.form.get('show_like_count', 'on') == 'on'
        }
        
        # Add to beginning of posts list
        posts.insert(0, new_post)
        
        # Update user's post count
        if user:
            user['posts_count'] = user.get('posts_count', 0) + 1
            users = load_users()
            for u in users:
                if u['id'] == current_user_id:
                    u['posts_count'] = user['posts_count']
                    break
            save_users(users)
        
        # Save posts
        save_posts(posts)
        
        return jsonify({
            'success': True,
            'post': new_post,
            'message': 'Post created successfully'
        })
        
    except Exception as e:
        print(f"Error creating post: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/posts/<int:post_id>/like', methods=['POST'])
def toggle_like(post_id):
    """Toggle like status for a post"""
    posts = load_posts()
    target_post = None
    
    for post in posts:
        if post['id'] == post_id:
            target_post = post
            # Toggle like status
            post['is_liked'] = not post.get('is_liked', False)
            # Update like count
            if post['is_liked']:
                post['likes_count'] = post.get('likes_count', 0) + 1
            else:
                post['likes_count'] = max(0, post.get('likes_count', 0) - 1)
            break
    
    if target_post:
        save_posts(posts)
        return jsonify({
            'success': True, 
            'is_liked': target_post.get('is_liked', False),
            'likes_count': target_post.get('likes_count', 0)
        })
    else:
        return jsonify({'success': False, 'error': 'Post not found'}), 404

@app.route('/api/posts/<int:post_id>/save', methods=['POST'])
def toggle_save(post_id):
    """Toggle save status for a post"""
    posts = load_posts()
    target_post = None
    
    for post in posts:
        if post['id'] == post_id:
            target_post = post
            post['is_saved'] = not post.get('is_saved', False)
            break
    
    if target_post:
        save_posts(posts)
        return jsonify({'success': True, 'is_saved': target_post.get('is_saved', False)})
    else:
        return jsonify({'success': False, 'error': 'Post not found'}), 404

@app.route('/api/posts/<int:post_id>/share', methods=['POST'])
def get_share_link(post_id):
    """Generate a shareable link for a post and increment share count"""
    posts = load_posts()
    target_post = None
    
    for post in posts:
        if post.get('id') == post_id:
            target_post = post
            # Increment share count when share link is requested
            post['shares_count'] = post.get('shares_count', 0) + 1
            break
    
    if not target_post:
        return jsonify({'success': False, 'error': 'Post not found'}), 404
    
    # Generate the shareable link
    share_link = request.url_root.rstrip('/') + url_for('view_post', post_id=post_id)
    
    # Save posts to persist the updated share count
    save_posts(posts)
    
    return jsonify({
        'success': True,
        'share_link': share_link,
        'post_id': post_id,
        'shares_count': target_post.get('shares_count', 0)
    })

@app.route('/api/posts/<int:post_id>/comments', methods=['GET'])
def get_post_comments(post_id):
    """Get comments for a post"""
    posts = load_posts()
    target_post = None
    
    for post in posts:
        if post['id'] == post_id:
            target_post = post
            break
    
    if target_post:
        comments = target_post.get('comments', [])
        return jsonify({'success': True, 'comments': comments})
    else:
        return jsonify({'success': False, 'error': 'Post not found'}), 404

@app.route('/api/posts/<int:post_id>/comments', methods=['POST'])
def post_comment(post_id):
    """Post a comment on a post or reply to a comment"""
    posts = load_posts()
    target_post = None
    
    data = request.get_json()
    comment_text = data.get('text', '').strip()
    parent_id = data.get('parent_id', None)  # ID of parent comment if this is a reply
    
    # Convert parent_id to int if it's provided (handles string from JavaScript)
    if parent_id is not None:
        try:
            parent_id = int(parent_id)
        except (ValueError, TypeError):
            return jsonify({'success': False, 'error': 'Invalid parent_id format'}), 400
    
    if not comment_text:
        return jsonify({'success': False, 'error': 'Comment text is required'}), 400
    
    for post in posts:
        if post['id'] == post_id:
            target_post = post
            # Initialize comments array if it doesn't exist
            if 'comments' not in post:
                post['comments'] = []
            
            # Generate new comment ID
            all_comment_ids = []
            def get_all_comment_ids(comments):
                for comment in comments:
                    all_comment_ids.append(comment.get('id', 0))
                    if 'replies' in comment and comment['replies']:
                        get_all_comment_ids(comment['replies'])
            
            get_all_comment_ids(post['comments'])
            new_comment_id = max(all_comment_ids, default=0) + 1
            
            # Add new comment
            new_comment = {
                'id': new_comment_id,
                'username': 'current_user',  # In production, get from session
                'text': comment_text,
                'time_ago': 'Just now',
                'avatar': 'avatar-2.jpg',
                'replies': []
            }
            
            if parent_id is not None:
                # This is a reply to an existing comment
                # Only allow replies to top-level comments (not to replies)
                def find_top_level_comment(comments, parent_id):
                    for comment in comments:
                        # Compare IDs as integers to handle type mismatches
                        comment_id = comment.get('id')
                        if comment_id is not None:
                            # Convert to int for comparison
                            try:
                                comment_id = int(comment_id)
                                if comment_id == parent_id:
                                    # Found the parent comment at top level
                                    return comment
                            except (ValueError, TypeError):
                                pass
                    return None
                
                parent_comment = find_top_level_comment(post['comments'], parent_id)
                if parent_comment:
                    # Add reply to top-level comment
                    if 'replies' not in parent_comment:
                        parent_comment['replies'] = []
                    parent_comment['replies'].append(new_comment)
                else:
                    return jsonify({'success': False, 'error': 'Parent comment not found or cannot reply to replies'}), 404
            else:
                # This is a top-level comment
                post['comments'].append(new_comment)
            
            # Update comment count (only count top-level comments, not replies)
            # Replies are visible but not counted
            # Ensure count is accurate by recalculating from actual comments array
            post['comments_count'] = len(post.get('comments', []))
            break
    
    if target_post:
        # Save posts to database
        save_result = save_posts(posts)
        if not save_result:
            print(f"Warning: Failed to save posts after adding comment/reply to post {post_id}")
            # Still return success since the comment was added to memory
            # In production, you might want to return an error here
        
        return jsonify({
            'success': True, 
            'comment': new_comment, 
            'comments_count': target_post.get('comments_count', 0),
            'parent_id': parent_id if parent_id is not None else None
        })
    else:
        return jsonify({'success': False, 'error': 'Post not found'}), 404

@app.route('/notifications')
@login_required
def notifications():
    """Render notifications page"""
    current_username = session.get('username')
    if not current_username:
        return redirect(url_for('login'))
    
    all_notifications = load_notifications()
    # Filter notifications for current user
    user_notifications = [
        n for n in all_notifications 
        if n.get('target_user') == current_username or (not n.get('target_user') and n.get('user') != current_username)
    ]
    return render_template('notifications.html', notifications=user_notifications)

@app.route('/api/notifications')
def api_notifications():
    """API endpoint to get all notifications"""
    notifications = load_notifications()
    return jsonify(notifications)

@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """Mark a specific notification as read"""
    current_username = session.get('username')
    if not current_username:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    notifications = load_notifications()
    target_notification = None
    
    for notification in notifications:
        if notification['id'] == notification_id:
            # Verify this notification belongs to the current user
            if (notification.get('target_user') == current_username or 
                (not notification.get('target_user') and notification.get('user') != current_username)):
                target_notification = notification
                notification['is_read'] = True
                break
    
    if target_notification:
        save_notifications(notifications)
        return jsonify({'success': True, 'is_read': True})
    else:
        return jsonify({'success': False, 'error': 'Notification not found'}), 404

@app.route('/api/notifications/read-all', methods=['POST'])
def mark_all_notifications_read():
    """Mark all notifications as read"""
    notifications = load_notifications()
    
    for notification in notifications:
        notification['is_read'] = True
    
    save_notifications(notifications)
    return jsonify({'success': True, 'read_count': len(notifications)})

@app.route('/api/notifications/unread-count')
@login_required
def get_unread_notifications_count():
    """Get count of unread notifications for current user"""
    current_username = session.get('username')
    if not current_username:
        return jsonify({'unread_count': 0, 'reply_count': 0})
    
    notifications = load_notifications()
    # Filter notifications for current user
    user_notifications = [
        n for n in notifications 
        if (n.get('target_user') == current_username or (not n.get('target_user') and n.get('user') != current_username))
        and not n.get('is_read', False)
    ]
    unread_count = len(user_notifications)
    
    # Count reply notifications specifically
    reply_count = sum(1 for n in user_notifications if n.get('type') == 'group_reply')
    
    return jsonify({'unread_count': unread_count, 'reply_count': reply_count})

@app.route('/api/messages/unread-count')
@login_required
def get_unread_messages_count():
    """Get count of chats with unread messages (1 per chat, not total messages)"""
    current_username = session.get('username')
    if not current_username or not validate_username(current_username):
        return jsonify({'unread_count': 0})
    
    all_conversations = load_messages()
    unread_chat_count = 0
    
    for conv in all_conversations:
        if not is_user_in_conversation(conv, current_username):
            continue
        
        conv_messages = conv.get('messages', [])
        if not conv_messages:
            continue
        
        # Count unread messages from current user's perspective
        unread_count = sum(1 for m in conv_messages 
                          if m.get('sender') != current_username and not m.get('is_read', False))
        
        # Count this chat as 1 if it has any unread messages
        if unread_count > 0:
            unread_chat_count += 1
    
    return jsonify({'unread_count': unread_chat_count})

@app.route('/events')
def events():
    """Render events page"""
    from datetime import datetime, timedelta
    events = load_events()
    categories = get_event_categories()
    
    # Calculate if event is new (created within last 7 days, similar to products)
    current_date = datetime.now().date()
    today_str = datetime.now().strftime('%Y-%m-%d')
    events_updated = False
    
    for event in events:
        try:
            # Ensure created_at exists, default to today if missing
            if 'created_at' not in event or not event.get('created_at'):
                event['created_at'] = today_str
                events_updated = True  # Mark that we need to save
            
            created_date_str = event.get('created_at', '')
            if created_date_str:
                created_date = datetime.strptime(created_date_str, '%Y-%m-%d').date()
                days_old = (current_date - created_date).days
                # Mark as new if created within last 7 days (0-7 days old)
                event['is_new'] = days_old <= 7 and days_old >= 0
            else:
                # If still empty, mark as new (just created)
                event['is_new'] = True
                event['created_at'] = today_str
                events_updated = True
        except Exception as e:
            print(f"Error calculating is_new for event {event.get('id')}: {e}")
            # Default to True if we can't parse, as it might be a new event
            event['is_new'] = True
            if 'created_at' not in event or not event.get('created_at'):
                event['created_at'] = today_str
                events_updated = True
    
    # Save events if we updated any created_at fields
    if events_updated:
        save_events(events)
    
    return render_template('events.html', events=events, categories=categories, get_category_icon=get_category_icon)

@app.route('/events/upload')
def upload_event():
    """Render event upload page"""
    return render_template('upload_event.html')

@app.route('/events/<int:event_id>')
def event_detail(event_id):
    """Render event detail page"""
    from datetime import datetime
    events = load_events()
    event = None
    
    for e in events:
        if e['id'] == event_id:
            event = e
            break
    
    if not event:
        return "Event not found", 404
    
    # Calculate if event is new (created within last 7 days, similar to products)
    current_date = datetime.now().date()
    today_str = datetime.now().strftime('%Y-%m-%d')
    event_updated = False
    
    try:
        # Ensure created_at exists, default to today if missing
        if 'created_at' not in event or not event.get('created_at'):
            event['created_at'] = today_str
            event_updated = True
        
        created_date_str = event.get('created_at', '')
        if created_date_str:
            created_date = datetime.strptime(created_date_str, '%Y-%m-%d').date()
            days_old = (current_date - created_date).days
            # Mark as new if created within last 7 days (0-7 days old)
            event['is_new'] = days_old <= 7 and days_old >= 0
        else:
            # If still empty, mark as new (just created)
            event['is_new'] = True
            event['created_at'] = today_str
            event_updated = True
    except Exception as e:
        print(f"Error calculating is_new for event {event.get('id')}: {e}")
        # Default to True if we can't parse, as it might be a new event
        event['is_new'] = True
        if 'created_at' not in event or not event.get('created_at'):
            event['created_at'] = today_str
            event_updated = True
    
    # Save event if we updated created_at
    if event_updated:
        events = load_events()
        for e in events:
            if e['id'] == event_id:
                e['created_at'] = event['created_at']
                save_events(events)
                break
    
    # Check if current user is the host
    current_username = session.get('username', '')
    is_host = event.get('host') == current_username or event.get('host_username') == current_username
    
    # Check if current user is attending
    is_attending = False
    if current_username and 'attendees' in event:
        is_attending = any(a.get('username') == current_username for a in event.get('attendees', []))
    event['is_attending'] = is_attending
    
    return render_template('event_detail.html', event=event, is_host=is_host, get_category_icon=get_category_icon, current_user=session)

@app.route('/api/events')
def api_events():
    """API endpoint to get all events"""
    events = load_events()
    return jsonify(events)

@app.route('/api/events', methods=['POST'])
def create_event():
    """Create a new event"""
    try:
        # Handle form data with file upload
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                # Generate unique filename
                filename = secure_filename(file.filename)
                file_extension = filename.rsplit('.', 1)[1].lower()
                unique_filename = f"{uuid.uuid4().hex}.{file_extension}"
                # Save to database/events folder
                events_dir = os.path.join('database', 'events')
                os.makedirs(events_dir, exist_ok=True)
                file_path = os.path.join(events_dir, unique_filename)
                file.save(file_path)
                featured_image = unique_filename
            else:
                featured_image = None
        else:
            featured_image = None
        
        # Get form data
        data = {
            'title': request.form.get('title'),
            'description': request.form.get('description'),
            'location': request.form.get('location'),
            'date': request.form.get('date'),
            'time': request.form.get('time'),
            'host': request.form.get('host'),
            'category': request.form.get('category', 'general')
        }
        
        # Validate required fields
        required_fields = ['title', 'description', 'location', 'date', 'time', 'host']
        for field in required_fields:
            if not data[field]:
                return jsonify({'success': False, 'error': f'Missing required field: {field}'}), 400
        
        # Load existing events
        events = load_events()
        
        # Generate new event ID
        new_id = max([event.get('id', 0) for event in events], default=0) + 1
        
        # Set created_at to current date if not provided or empty
        created_at = request.form.get('created_at', '').strip()
        if not created_at:
            from datetime import datetime
            created_at = datetime.now().strftime('%Y-%m-%d')
        else:
            try:
                from datetime import datetime
                # Validate date format
                datetime.strptime(created_at, '%Y-%m-%d')
            except ValueError:
                from datetime import datetime
                created_at = datetime.now().strftime('%Y-%m-%d')
        
        # Create new event
        new_event = {
            'id': new_id,
            'title': data['title'],
            'description': data['description'],
            'location': data['location'],
            'date': data['date'],
            'time': data['time'],
            'host': data['host'],
            'category': data['category'],
            'featured_image': featured_image,
            'attendees_count': 0,
            'created_at': created_at,
            'is_attending': False
        }
        
        # Add to events list
        events.append(new_event)
        
        # Save to database
        if save_events(events):
            return jsonify({'success': True, 'event': new_event}), 201
        else:
            return jsonify({'success': False, 'error': 'Failed to save event'}), 500
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/events/<int:event_id>/attend', methods=['POST'])
@login_required
def toggle_event_attendance(event_id):
    """Toggle attendance status for an event"""
    # Get current user from session
    current_username = session.get('username')
    current_user_id = session.get('user_id')
    current_full_name = session.get('full_name', current_username)
    current_avatar = session.get('avatar', 'avatar-1.jpg')
    
    if not current_username:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    # Get user from database to ensure we have latest info
    user = get_user_by_username(current_username)
    if user:
        current_avatar = user.get('avatar', current_avatar)
        current_full_name = user.get('full_name', current_full_name)
    
    current_user = {
        'username': current_username,
        'avatar': current_avatar,
        'name': current_full_name,
        'user_id': current_user_id
    }
    
    events = load_events()
    target_event = None
    
    for event in events:
        if event['id'] == event_id:
            target_event = event
            # Initialize attendees list if it doesn't exist
            if 'attendees' not in event:
                event['attendees'] = []
            
            # Check if user is already attending
            is_attending = any(a.get('username') == current_username for a in event.get('attendees', []))
            
            # Toggle attendance status
            if not is_attending:
            
            # Update attendees list
            if not 'attendees' in event:
                event['attendees'] = []
            
            if event['is_attending']:
                # Add user to attendees list
                event['attendees_count'] = event.get('attendees_count', 0) + 1
                # Check if user not already in list
                if not any(a['username'] == current_user['username'] for a in event['attendees']):
                    event['attendees'].append(current_user)
            else:
                # Remove user from attendees list
                event['attendees_count'] = max(0, event.get('attendees_count', 0) - 1)
                event['attendees'] = [a for a in event['attendees'] if a['username'] != current_user['username']]
            break
    
    if target_event:
        save_events(events)
        return jsonify({
            'success': True, 
            'is_attending': target_event.get('is_attending', False),
            'attendees_count': target_event.get('attendees_count', 0)
        })
    else:
        return jsonify({'success': False, 'error': 'Event not found'}), 404

@app.route('/api/events/<int:event_id>', methods=['GET'])
def get_event(event_id):
    """Get a single event by ID"""
    events = load_events()
    for event in events:
        if event['id'] == event_id:
            return jsonify({'success': True, 'event': event})
    return jsonify({'success': False, 'error': 'Event not found'}), 404

@app.route('/api/events/<int:event_id>', methods=['PUT'])
def update_event(event_id):
    """Update an event"""
    try:
        events = load_events()
        target_event = None
        
        for event in events:
            if event['id'] == event_id:
                target_event = event
                # Update event fields
                data = request.get_json()
                if 'title' in data:
                    event['title'] = data['title']
                if 'description' in data:
                    event['description'] = data['description']
                if 'location' in data:
                    event['location'] = data['location']
                if 'date' in data:
                    event['date'] = data['date']
                if 'time' in data:
                    event['time'] = data['time']
                if 'category' in data:
                    event['category'] = data['category']
                break
        
        if target_event:
            save_events(events)
            return jsonify({'success': True, 'event': target_event})
        else:
            return jsonify({'success': False, 'error': 'Event not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/events/<int:event_id>', methods=['DELETE'])
def delete_event(event_id):
    """Delete an event"""
    try:
        events = load_events()
        original_count = len(events)
        events = [e for e in events if e['id'] != event_id]
        
        if len(events) < original_count:
            save_events(events)
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Event not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/events/<int:event_id>/bookmark', methods=['POST'])
def toggle_event_bookmark(event_id):
    """Toggle bookmark status for an event"""
    events = load_events()
    target_event = None
    
    for event in events:
        if event['id'] == event_id:
            target_event = event
            event['is_bookmarked'] = not event.get('is_bookmarked', False)
            break
    
    if target_event:
        save_events(events)
        return jsonify({
            'success': True, 
            'is_bookmarked': target_event.get('is_bookmarked', False)
        })
    else:
        return jsonify({'success': False, 'error': 'Event not found'}), 404

@app.route('/api/events/<int:event_id>/report', methods=['POST'])
def report_event(event_id):
    """Report an event"""
    try:
        events = load_events()
        current_user = 'john_doe'
        target_event = None
        
        for event in events:
            if event['id'] == event_id:
                target_event = event
                if not 'reported_by' in event:
                    event['reported_by'] = []
                
                # Add user to reported_by list if not already there
                if current_user not in event['reported_by']:
                    event['reported_by'].append(current_user)
                break
        
        if target_event:
            save_events(events)
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Event not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/events/<int:event_id>/attendees', methods=['GET'])
def get_event_attendees(event_id):
    """Get list of attendees for an event"""
    events = load_events()
    for event in events:
        if event['id'] == event_id:
            attendees = event.get('attendees', [])
            return jsonify({'success': True, 'attendees': attendees})
    return jsonify({'success': False, 'error': 'Event not found'}), 404

@app.route('/api/events/<int:event_id>/comments', methods=['POST'])
def add_event_comment(event_id):
    """Add a comment to an event"""
    try:
        from datetime import datetime
        events = load_events()
        current_user = {'username': 'john_doe', 'avatar': 'avatar-1.jpg', 'name': 'John Doe'}
        target_event = None
        
        for event in events:
            if event['id'] == event_id:
                target_event = event
                if not 'comments' in event:
                    event['comments'] = []
                
                # Get comment text from request
                data = request.get_json()
                comment_text = data.get('text', '').strip()
                
                if not comment_text:
                    return jsonify({'success': False, 'error': 'Comment text is required'}), 400
                
                # Generate new comment ID
                new_comment_id = max([c.get('id', 0) for c in event['comments']], default=0) + 1
                
                # Create new comment
                new_comment = {
                    'id': new_comment_id,
                    'username': current_user['username'],
                    'avatar': current_user['avatar'],
                    'name': current_user['name'],
                    'text': comment_text,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M')
                }
                
                event['comments'].append(new_comment)
                break
        
        if target_event:
            save_events(events)
            return jsonify({'success': True, 'comment': new_comment})
        else:
            return jsonify({'success': False, 'error': 'Event not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/events/<int:event_id>/comments/<int:comment_id>', methods=['PUT'])
@login_required
def update_event_comment(event_id, comment_id):
    """Update a comment on an event"""
    try:
        # Get current user from session
        current_username = session.get('username')
        if not current_username:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
        events = load_events()
        target_event = None
        target_comment = None
        
        for event in events:
            if event['id'] == event_id:
                target_event = event
                for comment in event.get('comments', []):
                    if comment['id'] == comment_id:
                        # Check if user owns the comment
                        if comment['username'] == current_user:
                            target_comment = comment
                            data = request.get_json()
                            comment_text = data.get('text', '').strip()
                            
                            if not comment_text:
                                return jsonify({'success': False, 'error': 'Comment text is required'}), 400
                            
                            comment['text'] = comment_text
                        else:
                            return jsonify({'success': False, 'error': 'Not authorized'}), 403
                        break
                break
        
        if target_event and target_comment:
            save_events(events)
            return jsonify({'success': True, 'comment': target_comment})
        elif target_event and not target_comment:
            return jsonify({'success': False, 'error': 'Comment not found'}), 404
        else:
            return jsonify({'success': False, 'error': 'Event not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/events/<int:event_id>/comments/<int:comment_id>', methods=['DELETE'])
def delete_event_comment(event_id, comment_id):
    """Delete a comment from an event"""
    try:
        events = load_events()
        current_user = 'john_doe'
        target_event = None
        comment_found = False
        
        for event in events:
            if event['id'] == event_id:
                target_event = event
                original_count = len(event.get('comments', []))
                
                # Filter out the comment if user owns it
                event['comments'] = [c for c in event.get('comments', []) 
                                    if not (c['id'] == comment_id and c['username'] == current_user)]
                
                comment_found = len(event['comments']) < original_count
                break
        
        if target_event and comment_found:
            save_events(events)
            return jsonify({'success': True})
        elif target_event and not comment_found:
            return jsonify({'success': False, 'error': 'Comment not found or not authorized'}), 404
        else:
            return jsonify({'success': False, 'error': 'Event not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/events/new-count')
def get_new_events_count():
    """Get count of new events (created within last 24 hours)"""
    from datetime import datetime
    events = load_events()
    current_date = datetime.now().date()
    new_count = 0
    
    for event in events:
        try:
            created_date = datetime.strptime(event.get('created_at', ''), '%Y-%m-%d').date()
            if (current_date - created_date).days == 0:
                new_count += 1
        except:
            pass
    
    return jsonify({'new_count': new_count})

@app.route('/api/events/categories')
def api_event_categories():
    """API endpoint to get event categories"""
    categories = get_event_categories()
    category_data = []
    for category in categories:
        category_data.append({
            'name': category,
            'icon': get_category_icon(category),
            'display_name': category.replace('_', ' ').title()
        })
    return jsonify(category_data)

@app.route('/static/images/events/<filename>')
def serve_event_image(filename):
    """Serve event images"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/database/events/<filename>')
def serve_event_image_db(filename):
    """Serve event images from database/events folder"""
    events_dir = os.path.join('database', 'events')
    return send_from_directory(events_dir, filename)

@app.route('/database/groups/<filename>')
def serve_group_image(filename):
    """Serve group images from database/groups folder"""
    groups_dir = os.path.join('database', 'groups')
    return send_from_directory(groups_dir, filename)

# ==================== Helper Functions for New Pages ====================

def load_reels():
    """Load reels from JSON database"""
    try:
        with open('database/reels.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('reels', [])
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        return []

def save_reels(reels):
    """Save reels to JSON database"""
    try:
        with open('database/reels.json', 'w', encoding='utf-8') as f:
            json.dump({'reels': reels}, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Error saving reels: {e}")
        raise

def load_users():
    """Load users from JSON database"""
    try:
        with open('database/users.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('users', [])
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        return []

def save_users(users):
    """Save users to JSON database"""
    try:
        if not isinstance(users, list):
            print("Error: users must be a list")
            return False
            
        os.makedirs('database', exist_ok=True)
        with open('database/users.json', 'w', encoding='utf-8') as f:
            json.dump({'users': users}, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error saving users: {e}")
        return False

def get_user_by_username(username):
    """Get user by username"""
    users = load_users()
    for user in users:
        if user.get('username') == username:
            return user
    return None

def get_user_by_email(email):
    """Get user by email"""
    users = load_users()
    for user in users:
        if user.get('email') == email:
            return user
    return None


# ============================================================================
# SECURE MESSAGE SYSTEM - Security Utilities
# ============================================================================

# Rate limiting configuration
MAX_MESSAGES_PER_MINUTE = 30
MAX_MESSAGES_PER_HOUR = 500
RATE_LIMIT_WINDOW_MINUTE = 60  # seconds
RATE_LIMIT_WINDOW_HOUR = 3600  # seconds

def sanitize_message_text(text):
    """
    Sanitize message text to prevent XSS attacks and validate input.
    Escapes HTML to prevent XSS while preserving newlines for frontend display.
    """
    if not isinstance(text, str):
        return ""
    
    # Remove null bytes and control characters (except newlines, carriage returns, and tabs)
    # Keep \n (newline), \r (carriage return), \t (tab)
    text = re.sub(r'[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]', '', text)
    
    # Limit length (max 5000 characters)
    if len(text) > 5000:
        text = text[:5000]
    
    # Escape HTML to prevent XSS attacks
    # This converts <script> to &lt;script&gt; etc.
    text = html.escape(text)
    
    # Convert newlines back to <br> tags after escaping (safe since HTML is escaped)
    # This allows frontend to display multi-line messages
    text = text.replace('\n', '<br>')
    # Convert tabs to spaces
    text = text.replace('\t', '    ')
    
    return text.strip()

def validate_username(username):
    """
    Validate username format - only alphanumeric, underscore, and hyphen.
    Prevents injection attacks through usernames.
    """
    if not isinstance(username, str):
        return False
    # Only allow alphanumeric, underscore, hyphen, and ensure reasonable length
    if len(username) < 1 or len(username) > 50:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', username))

def check_rate_limit(username):
    """
    Check if user has exceeded rate limits for sending messages.
    Uses session-based tracking (simple approach without external dependencies).
    Returns (allowed, error_message)
    """
    if not username:
        return False, "Invalid user"
    
    now = time.time()
    session_key = f"msg_rate_limit_{username}"
    
    # Initialize rate limit tracking if not exists
    if session_key not in session:
        session[session_key] = {
            'minute': {'count': 0, 'reset_time': now + RATE_LIMIT_WINDOW_MINUTE},
            'hour': {'count': 0, 'reset_time': now + RATE_LIMIT_WINDOW_HOUR}
        }
    
    rate_data = session[session_key]
    
    # Check and reset minute window if expired
    if now > rate_data['minute']['reset_time']:
        rate_data['minute'] = {'count': 0, 'reset_time': now + RATE_LIMIT_WINDOW_MINUTE}
    
    # Check and reset hour window if expired
    if now > rate_data['hour']['reset_time']:
        rate_data['hour'] = {'count': 0, 'reset_time': now + RATE_LIMIT_WINDOW_HOUR}
    
    # Check limits
    if rate_data['minute']['count'] >= MAX_MESSAGES_PER_MINUTE:
        return False, f"Rate limit exceeded: Maximum {MAX_MESSAGES_PER_MINUTE} messages per minute"
    
    if rate_data['hour']['count'] >= MAX_MESSAGES_PER_HOUR:
        return False, f"Rate limit exceeded: Maximum {MAX_MESSAGES_PER_HOUR} messages per hour"
    
    # Increment counters
    rate_data['minute']['count'] += 1
    rate_data['hour']['count'] += 1
    session[session_key] = rate_data
    
    return True, None

def is_user_in_conversation(conversation, username):
    """
    Securely check if a user is part of a conversation.
    Returns True if user is a participant, False otherwise.
    Handles both perspectives: when user is the conversation partner or a message sender.
    Also handles new conversations where the user is the creator but hasn't sent messages yet.
    """
    if not conversation or not username or not validate_username(username):
        return False
    
    conv_username = conversation.get('user', {}).get('username')
    messages = conversation.get('messages', [])
    
    # Case 1: User is the conversation partner (conversation was created with this user)
    if conv_username == username:
        return True
    
    # Case 2: User has sent messages in this conversation
    for message in messages:
        sender = message.get('sender')
        if sender == username and validate_username(sender):
            return True
    
    # Case 3: Check if user is the creator of the conversation (for new conversations with no messages)
    # When a conversation is created, last_message.sender is set to the creator
    if not messages or len(messages) == 0:
        last_message = conversation.get('last_message', {})
        last_message_sender = last_message.get('sender')
        if last_message_sender == username and validate_username(last_message_sender):
            return True
    
    # Case 4: Check reverse perspective - if conversation partner sent messages to this user
    # This handles cases where someone started a conversation with the current user
    if conv_username and conv_username != username:
        # If there are messages from the conversation partner, the current user should see them
        for message in messages:
            sender = message.get('sender')
            if sender and sender != username and validate_username(sender):
                # If the conversation partner has sent messages, current user should have access
                # This allows users to see conversations started with them
                return True
    
    return False

def load_messages():
    """Load messages from JSON database with validation"""
    try:
        with open('database/messages.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            conversations = data.get('conversations', [])
            
            # Validate structure
            if not isinstance(conversations, list):
                return []
            
            # Validate each conversation structure
            valid_conversations = []
            for conv in conversations:
                if isinstance(conv, dict) and 'id' in conv:
                    # Ensure required fields exist
                    if 'user' not in conv:
                        conv['user'] = {}
                    if 'messages' not in conv:
                        conv['messages'] = []
                    if 'last_message' not in conv:
                        conv['last_message'] = {}
                    if 'unread_count' not in conv:
                        conv['unread_count'] = 0
                    
                    # Validate user data
                    if not isinstance(conv['user'], dict):
                        conv['user'] = {}
                    if not validate_username(conv['user'].get('username', '')):
                        continue  # Skip invalid conversations
                    
                    # Validate messages
                    if not isinstance(conv['messages'], list):
                        conv['messages'] = []
                    
                    valid_conversations.append(conv)
            
            return valid_conversations
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        return []
    except Exception as e:
        print(f"Error loading messages: {e}")
        return []

def save_messages(conversations):
    """
    Save messages to JSON database with security validation.
    Validates all data before saving to prevent injection attacks.
    Note: Message text should already be sanitized before calling this function.
    """
    try:
        # Validate conversations data
        if not isinstance(conversations, list):
            print("Error: conversations must be a list")
            return False
        
        # Validate each conversation before saving
        validated_conversations = []
        for conv in conversations:
            if not isinstance(conv, dict):
                print(f"Warning: Skipping non-dict conversation: {type(conv)}")
                continue
            
            # Ensure required fields
            if 'id' not in conv or not isinstance(conv['id'], int):
                print(f"Warning: Skipping conversation with invalid ID: {conv.get('id')}")
                continue
            
            # Validate user
            if 'user' not in conv or not isinstance(conv['user'], dict):
                print(f"Warning: Skipping conversation {conv.get('id')} with invalid user")
                continue
            
            username = conv['user'].get('username', '')
            if not validate_username(username):
                print(f"Warning: Skipping conversation {conv.get('id')} with invalid username: {username}")
                continue
            
            # Validate messages
            if 'messages' not in conv:
                conv['messages'] = []
            elif not isinstance(conv['messages'], list):
                conv['messages'] = []
            
            # Validate and filter messages (don't re-sanitize - text should already be sanitized)
            validated_messages = []
            for msg in conv['messages']:
                if not isinstance(msg, dict):
                    continue
                
                # Validate sender
                sender = msg.get('sender')
                if not sender or not validate_username(sender):
                    print(f"Warning: Skipping message with invalid sender: {sender}")
                    continue
                
                # Ensure message has text field (even if empty)
                if 'text' not in msg:
                    msg['text'] = ''
                
                # Validate message text is a string
                if not isinstance(msg['text'], str):
                    print(f"Warning: Skipping message with non-string text")
                    continue
                
                # Note: We don't re-sanitize here because text should already be sanitized
                # Re-sanitizing would break already-escaped HTML like &lt;br&gt;
                validated_messages.append(msg)
            
            # Replace messages with validated messages
            conv['messages'] = validated_messages
            
            # Ensure other required fields exist
            if 'last_message' not in conv:
                conv['last_message'] = {}
            if 'unread_count' not in conv:
                conv['unread_count'] = 0
            
            validated_conversations.append(conv)
        
        os.makedirs('database', exist_ok=True)
        with open('database/messages.json', 'w', encoding='utf-8') as f:
            json.dump({'conversations': validated_conversations}, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error saving messages: {e}")
        import traceback
        traceback.print_exc()
        return False

def load_groups():
    """Load groups from JSON database - optimized for fast loading"""
    try:
        # Use faster file reading with buffering
        with open('database/groups.json', 'r', encoding='utf-8') as f:
            # Use parse_float and parse_int for faster parsing if needed
            data = json.load(f)
            groups = data.get('groups', [])
            # Return empty list if groups is None
            return groups if groups else []
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        return []
    except Exception as e:
        print(f"Error loading groups: {e}")
        return []

def save_groups(groups):
    """Save groups to JSON database"""
    global _category_cache, _category_cache_groups_count
    
    try:
        # Validate groups data
        if not isinstance(groups, list):
            print("Error: groups must be a list")
            return False
            
        os.makedirs('database', exist_ok=True)
        with open('database/groups.json', 'w', encoding='utf-8') as f:
            json.dump({'groups': groups}, f, indent=2, ensure_ascii=False)
        
        # Invalidate category cache after saving
        _category_cache = None
        _category_cache_groups_count = 0
        
        return True
    except Exception as e:
        print(f"Error saving groups: {e}")
        return False

# Cache for categories to avoid reloading groups
_category_cache = None
_category_cache_groups_count = 0

def get_group_categories():
    """Get unique categories from groups - with caching for performance"""
    global _category_cache, _category_cache_groups_count
    
    # Load groups to check if cache is still valid
    groups = load_groups()
    current_groups_count = len(groups)
    
    # Return cached categories if groups count hasn't changed
    if _category_cache is not None and _category_cache_groups_count == current_groups_count:
        return _category_cache
    
    # Recalculate categories
    categories = set()
    for group in groups:
        category = group.get('category')
        if category:
            categories.add(category)
    
    _category_cache = sorted(list(categories))
    _category_cache_groups_count = current_groups_count
    return _category_cache

def load_settings():
    """Load settings from JSON database"""
    try:
        with open('database/settings.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('settings', {})
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}

def format_number(num):
    """Format number for display (e.g., 1000 -> 1K)"""
    if num >= 1000000:
        return f"{num / 1000000:.1f}M"
    elif num >= 1000:
        return f"{num / 1000:.1f}K"
    return str(num)

# Add format_number as a template filter
@app.template_filter('format_number')
def format_number_filter(num):
    """Template filter to format numbers"""
    return format_number(num)

# ==================== New Page Routes ====================

@app.route('/explore')
def explore():
    """Render search/explore page with optional search query"""
    query = request.args.get('q', '').strip()
    filter_type = request.args.get('filter', 'all')
    
    # If no query, show empty results
    if not query:
        return render_template('explore.html', 
                             query='', 
                             filter_type=filter_type,
                             results={'users': [], 'posts': [], 'events': [], 'groups': []},
                             total_results=0)
    
    # Perform search from database
    results = {
        'users': [],
        'posts': [],
        'groups': [],
        'events': []
    }
    
    query_lower = query.lower()
    
    # Search Users from database
    users = load_users()
    for user in users:
        if (query_lower in user.get('username', '').lower() or 
            query_lower in user.get('full_name', '').lower() or 
            query_lower in user.get('bio', '').lower()):
            results['users'].append(user)
    
    # Search Posts from database
    posts = load_posts()
    for post in posts:
        if (query_lower in post.get('caption', '').lower() or 
            query_lower in post.get('username', '').lower() or
            (post.get('user') and query_lower in post.get('user', {}).get('username', '').lower())):
            results['posts'].append(post)
    
    # Search Groups from database
    groups = load_groups()
    for group in groups:
        if (query_lower in group.get('name', '').lower() or 
            query_lower in group.get('description', '').lower() or 
            query_lower in group.get('category', '').lower()):
            results['groups'].append(group)
    
    # Search Events from database
    events = load_events()
    for event in events:
        if (query_lower in event.get('title', '').lower() or 
            query_lower in event.get('description', '').lower() or 
            query_lower in event.get('location', '').lower() or
            query_lower in event.get('category', '').lower() or
            query_lower in event.get('host', '').lower() or
            query_lower in event.get('host_username', '').lower()):
            results['events'].append(event)
    
    total_results = (len(results['users']) + len(results['posts']) + 
                    len(results['groups']) + len(results['events']))
    
    return render_template('explore.html', 
                         query=query, 
                         filter_type=filter_type,
                         results=results,
                         total_results=total_results)

@app.route('/reels')
def reels():
    """Render reels page"""
    reels = load_reels()
    return render_template('reels.html', reels=reels)

@app.route('/create')
def create():
    """Render create post page"""
    return render_template('create.html')

@app.route('/preview-post')
def preview_post():
    """Render preview post page"""
    return render_template('preview_post.html')

@app.route('/shop')
def shop():
    """Render shop page"""
    from datetime import datetime, timedelta
    products = load_shop()
    categories = get_shop_categories()
    search_query = request.args.get('q', '').strip().lower()
    
    # Calculate if product is new (created within last 7 days)
    current_date = datetime.now().date()
    today_str = datetime.now().strftime('%Y-%m-%d')
    
    for product in products:
        try:
            # Ensure created_at exists, default to today if missing
            if 'created_at' not in product or not product.get('created_at'):
                product['created_at'] = today_str
            
            created_date_str = product.get('created_at', '')
            if created_date_str:
                created_date = datetime.strptime(created_date_str, '%Y-%m-%d').date()
                days_old = (current_date - created_date).days
                # Mark as new if created within last 7 days
                product['is_new'] = days_old <= 7 and days_old >= 0
            else:
                # If still empty, mark as new (just created)
                product['is_new'] = True
        except Exception as e:
            print(f"Error calculating is_new for product {product.get('id')}: {e}")
            product['is_new'] = False
    
    # Filter products by search query if provided
    if search_query:
        filtered_products = []
        for product in products:
            # Search in product name, description, category, and seller
            product_name = product.get('name', '').lower()
            product_desc = product.get('description', '').lower()
            product_category = product.get('category', '').lower()
            product_seller = product.get('seller', '').lower()
            
            if (search_query in product_name or 
                search_query in product_desc or 
                search_query in product_category or 
                search_query in product_seller):
                filtered_products.append(product)
        products = filtered_products
    
    # Sort products: new products first, then by created date (newest first)
    def sort_key(product):
        # Return tuple: (not is_new, -days_old)
        # This ensures is_new=True products come first (False < True)
        # Within each group, sort by newest first
        is_new = product.get('is_new', False)
        try:
            created_date_str = product.get('created_at', today_str)
            created_date = datetime.strptime(created_date_str, '%Y-%m-%d').date()
            days_old = (current_date - created_date).days
        except:
            days_old = 0
        # Return (0 for new, 1 for old), (-days_old for reverse date sort)
        return (0 if is_new else 1, -days_old)
    
    products = sorted(products, key=sort_key)
    
    return render_template('shop.html', products=products, categories=categories, 
                         get_shop_category_icon=get_shop_category_icon, search_query=search_query)

@app.route('/shop/upload')
def upload_product():
    """Render product upload page"""
    return render_template('upload_product.html')

@app.route('/shop/<int:product_id>')
def product_detail(product_id):
    """Render product detail page"""
    from datetime import datetime
    products = load_shop()
    product = None
    
    for p in products:
        if p['id'] == product_id:
            product = p
            break
    
    if not product:
        return "Product not found", 404
    
    # Calculate if product is new (created within last 7 days)
    try:
        # Ensure created_at exists, default to today if missing
        current_date = datetime.now().date()
        today_str = datetime.now().strftime('%Y-%m-%d')
        
        if 'created_at' not in product or not product.get('created_at'):
            product['created_at'] = today_str
        
        created_date_str = product.get('created_at', '')
        if created_date_str:
            created_date = datetime.strptime(created_date_str, '%Y-%m-%d').date()
            days_old = (current_date - created_date).days
            # Mark as new if created within last 7 days
            product['is_new'] = days_old <= 7 and days_old >= 0
        else:
            # If still empty, mark as new (just created)
            product['is_new'] = True
    except Exception as e:
        print(f"Error calculating is_new for product {product.get('id')}: {e}")
        product['is_new'] = False
    
    # Check if current user is the seller
    current_username = session.get('username', 'john_doe')
    is_seller = product.get('seller_username') == current_username
    
    # Increment views counter
    product['views'] = product.get('views', 0) + 1
    # Save updated views to database
    products = load_shop()
    for p in products:
        if p['id'] == product_id:
            p['views'] = product['views']
            break
    save_shop(products)
    
    return render_template('shop_detail.html', product=product, is_seller=is_seller, get_shop_category_icon=get_shop_category_icon)

@app.route('/api/shop')
def api_shop():
    """API endpoint to get all products"""
    from datetime import datetime
    products = load_shop()
    
    # Calculate if product is new (created within last 7 days)
    current_date = datetime.now().date()
    today_str = datetime.now().strftime('%Y-%m-%d')
    
    for product in products:
        try:
            # Ensure created_at exists, default to today if missing
            if 'created_at' not in product or not product.get('created_at'):
                product['created_at'] = today_str
            
            created_date_str = product.get('created_at', '')
            if created_date_str:
                created_date = datetime.strptime(created_date_str, '%Y-%m-%d').date()
                days_old = (current_date - created_date).days
                # Mark as new if created within last 7 days
                product['is_new'] = days_old <= 7 and days_old >= 0
            else:
                # If still empty, mark as new (just created)
                product['is_new'] = True
        except Exception as e:
            print(f"Error calculating is_new for product {product.get('id')}: {e}")
            product['is_new'] = False
    
    return jsonify(products)

@app.route('/api/shop', methods=['POST'])
def create_product():
    """Create a new product"""
    try:
        # Handle form data with file upload
        featured_image = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                # Generate unique filename
                filename = secure_filename(file.filename)
                file_extension = filename.rsplit('.', 1)[1].lower()
                unique_filename = f"{uuid.uuid4().hex}.{file_extension}"
                
                # Create shop directory if it doesn't exist - use database folder
                shop_dir = os.path.join('database', 'shop')
                os.makedirs(shop_dir, exist_ok=True)
                
                file_path = os.path.join(shop_dir, unique_filename)
                file.save(file_path)
                featured_image = unique_filename
        
        if not featured_image:
            return jsonify({'success': False, 'error': 'Product image is required'}), 400
        
        # Get form data
        from datetime import datetime
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        price_str = request.form.get('price', '').strip()
        seller = request.form.get('seller', '').strip()
        category = request.form.get('category', '').strip()
        stock_str = request.form.get('stock', '0').strip()
        created_at = request.form.get('created_at', '').strip()
        
        # Validate required fields
        if not name:
            return jsonify({'success': False, 'error': 'Product name is required'}), 400
        if not description:
            return jsonify({'success': False, 'error': 'Product description is required'}), 400
        if not price_str:
            return jsonify({'success': False, 'error': 'Product price is required'}), 400
        if not seller:
            return jsonify({'success': False, 'error': 'Seller name is required'}), 400
        if not category:
            return jsonify({'success': False, 'error': 'Product category is required'}), 400
        
        # Validate and convert price
        try:
            price = float(price_str)
            if price < 0:
                return jsonify({'success': False, 'error': 'Price must be a positive number'}), 400
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid price format'}), 400
        
        # Validate and convert stock
        try:
            stock = int(stock_str)
            if stock < 0:
                return jsonify({'success': False, 'error': 'Stock must be a positive number'}), 400
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid stock format'}), 400
        
        # Set created_at to current date if not provided
        if not created_at:
            created_at = datetime.now().strftime('%Y-%m-%d')
        else:
            try:
                datetime.strptime(created_at, '%Y-%m-%d')
            except ValueError:
                created_at = datetime.now().strftime('%Y-%m-%d')
        
        # Load existing products
        products = load_shop()
        
        # Generate new product ID
        new_id = max([product.get('id', 0) for product in products], default=0) + 1
        
        # Get current user from session
        seller_username = session.get('username', 'john_doe')
        
        # Create new product
        new_product = {
            'id': new_id,
            'name': name,
            'description': description,
            'price': round(price, 2),
            'currency': '$',
            'seller': seller,
            'seller_username': seller_username,
            'category': category,
            'featured_image': featured_image,
            'stock': stock,
            'views': 0,
            'created_at': created_at,
            'is_favorite': False,
            'is_bookmarked': False,
            'reviews': [],
            'reported_by': []
        }
        
        # Add to products list
        products.append(new_product)
        
        # Save to database
        if save_shop(products):
            return jsonify({'success': True, 'product': new_product}), 201
        else:
            return jsonify({'success': False, 'error': 'Failed to save product to database'}), 500
            
    except Exception as e:
        import traceback
        print(f"Error creating product: {e}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'}), 500

@app.route('/api/shop/<int:product_id>/favorite', methods=['POST'])
def toggle_product_favorite(product_id):
    """Toggle favorite status for a product"""
    products = load_shop()
    target_product = None
    
    for product in products:
        if product['id'] == product_id:
            target_product = product
            product['is_favorite'] = not product.get('is_favorite', False)
            break
    
    if target_product:
        save_shop(products)
        return jsonify({
            'success': True, 
            'is_favorite': target_product.get('is_favorite', False)
        })
    else:
        return jsonify({'success': False, 'error': 'Product not found'}), 404

@app.route('/api/shop/<int:product_id>', methods=['GET'])
def get_product(product_id):
    """Get a single product by ID"""
    from datetime import datetime
    products = load_shop()
    for product in products:
        if product['id'] == product_id:
            # Calculate if product is new (created within last 7 days)
            try:
                # Ensure created_at exists, default to today if missing
                current_date = datetime.now().date()
                today_str = datetime.now().strftime('%Y-%m-%d')
                
                if 'created_at' not in product or not product.get('created_at'):
                    product['created_at'] = today_str
                
                created_date_str = product.get('created_at', '')
                if created_date_str:
                    created_date = datetime.strptime(created_date_str, '%Y-%m-%d').date()
                    days_old = (current_date - created_date).days
                    # Mark as new if created within last 7 days
                    product['is_new'] = days_old <= 7 and days_old >= 0
                else:
                    # If still empty, mark as new (just created)
                    product['is_new'] = True
            except Exception as e:
                print(f"Error calculating is_new for product {product.get('id')}: {e}")
                product['is_new'] = False
            return jsonify({'success': True, 'product': product})
    return jsonify({'success': False, 'error': 'Product not found'}), 404

@app.route('/api/shop/<int:product_id>', methods=['PUT'])
def update_product(product_id):
    """Update a product"""
    try:
        products = load_shop()
        target_product = None
        
        for product in products:
            if product['id'] == product_id:
                target_product = product
                # Update product fields
                data = request.get_json()
                if 'name' in data:
                    product['name'] = data['name']
                if 'description' in data:
                    product['description'] = data['description']
                if 'price' in data:
                    product['price'] = float(data['price'])
                if 'stock' in data:
                    product['stock'] = int(data['stock'])
                if 'category' in data:
                    product['category'] = data['category']
                break
        
        if target_product:
            save_shop(products)
            return jsonify({'success': True, 'product': target_product})
        else:
            return jsonify({'success': False, 'error': 'Product not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/shop/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    """Delete a product"""
    try:
        products = load_shop()
        original_count = len(products)
        products = [p for p in products if p['id'] != product_id]
        
        if len(products) < original_count:
            save_shop(products)
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Product not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/shop/<int:product_id>/bookmark', methods=['POST'])
def toggle_product_bookmark(product_id):
    """Toggle bookmark status for a product"""
    products = load_shop()
    target_product = None
    
    for product in products:
        if product['id'] == product_id:
            target_product = product
            product['is_bookmarked'] = not product.get('is_bookmarked', False)
            break
    
    if target_product:
        save_shop(products)
        return jsonify({
            'success': True, 
            'is_bookmarked': target_product.get('is_bookmarked', False)
        })
    else:
        return jsonify({'success': False, 'error': 'Product not found'}), 404

@app.route('/api/shop/<int:product_id>/report', methods=['POST'])
def report_product(product_id):
    """Report a product"""
    try:
        products = load_shop()
        current_user = 'john_doe'
        target_product = None
        
        for product in products:
            if product['id'] == product_id:
                target_product = product
                if not 'reported_by' in product:
                    product['reported_by'] = []
                
                # Add user to reported_by list if not already there
                if current_user not in product['reported_by']:
                    product['reported_by'].append(current_user)
                break
        
        if target_product:
            save_shop(products)
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Product not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/shop/<int:product_id>/reviews', methods=['POST'])
def add_product_review(product_id):
    """Add a review to a product"""
    try:
        from datetime import datetime
        products = load_shop()
        current_user = {'username': 'john_doe', 'avatar': 'avatar-1.jpg', 'name': 'John Doe'}
        target_product = None
        
        for product in products:
            if product['id'] == product_id:
                target_product = product
                if not 'reviews' in product:
                    product['reviews'] = []
                
                # Get review data from request
                data = request.get_json()
                review_text = data.get('text', '').strip()
                rating = data.get('rating', 5)
                
                if not review_text:
                    return jsonify({'success': False, 'error': 'Review text is required'}), 400
                
                # Generate new review ID
                new_review_id = max([r.get('id', 0) for r in product['reviews']], default=0) + 1
                
                # Create new review
                new_review = {
                    'id': new_review_id,
                    'username': current_user['username'],
                    'avatar': current_user['avatar'],
                    'name': current_user['name'],
                    'text': review_text,
                    'rating': rating,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M')
                }
                
                product['reviews'].append(new_review)
                break
        
        if target_product:
            save_shop(products)
            return jsonify({'success': True, 'review': new_review})
        else:
            return jsonify({'success': False, 'error': 'Product not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/shop/<int:product_id>/reviews/<int:review_id>', methods=['PUT'])
def update_product_review(product_id, review_id):
    """Update a review on a product"""
    try:
        products = load_shop()
        current_user = 'john_doe'
        target_product = None
        target_review = None
        
        for product in products:
            if product['id'] == product_id:
                target_product = product
                for review in product.get('reviews', []):
                    if review['id'] == review_id:
                        # Check if user owns the review
                        if review['username'] == current_user:
                            target_review = review
                            data = request.get_json()
                            review_text = data.get('text', '').strip()
                            
                            if not review_text:
                                return jsonify({'success': False, 'error': 'Review text is required'}), 400
                            
                            review['text'] = review_text
                            if 'rating' in data:
                                review['rating'] = data['rating']
                        else:
                            return jsonify({'success': False, 'error': 'Not authorized'}), 403
                        break
                break
        
        if target_product and target_review:
            save_shop(products)
            return jsonify({'success': True, 'review': target_review})
        elif target_product and not target_review:
            return jsonify({'success': False, 'error': 'Review not found'}), 404
        else:
            return jsonify({'success': False, 'error': 'Product not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/shop/<int:product_id>/reviews/<int:review_id>', methods=['DELETE'])
def delete_product_review(product_id, review_id):
    """Delete a review from a product"""
    try:
        products = load_shop()
        current_user = 'john_doe'
        target_product = None
        review_found = False
        
        for product in products:
            if product['id'] == product_id:
                target_product = product
                original_count = len(product.get('reviews', []))
                
                # Filter out the review if user owns it
                product['reviews'] = [r for r in product.get('reviews', []) 
                                    if not (r['id'] == review_id and r['username'] == current_user)]
                
                review_found = len(product['reviews']) < original_count
                break
        
        if target_product and review_found:
            save_shop(products)
            return jsonify({'success': True})
        elif target_product and not review_found:
            return jsonify({'success': False, 'error': 'Review not found or not authorized'}), 404
        else:
            return jsonify({'success': False, 'error': 'Product not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/shop/new-count')
def get_new_products_count():
    """Get count of new products (created within last 24 hours)"""
    from datetime import datetime
    products = load_shop()
    current_date = datetime.now().date()
    new_count = 0
    
    for product in products:
        try:
            created_date = datetime.strptime(product.get('created_at', ''), '%Y-%m-%d').date()
            if (current_date - created_date).days == 0:
                new_count += 1
        except:
            pass
    
    return jsonify({'new_count': new_count})

@app.route('/api/shop/categories')
def api_shop_categories():
    """API endpoint to get shop categories"""
    categories = get_shop_categories()
    category_data = []
    for category in categories:
        category_data.append({
            'name': category,
            'icon': get_shop_category_icon(category),
            'display_name': category.replace('_', ' ').title()
        })
    return jsonify(category_data)

@app.route('/database/shop/<filename>')
def serve_shop_image_db(filename):
    """Serve shop images from database/shop folder"""
    shop_dir = os.path.join('database', 'shop')
    return send_from_directory(shop_dir, filename)

# Legacy route - kept for backward compatibility but redirects to database folder
@app.route('/static/images/shop/<filename>')
def serve_shop_image(filename):
    """Legacy route - redirects to database folder"""
    shop_dir = os.path.join('database', 'shop')
    return send_from_directory(shop_dir, filename)

@app.route('/database/avatars/<filename>')
def serve_avatar(filename):
    """Serve user avatars from database/avatars folder"""
    avatars_dir = os.path.join('database', 'avatars')
    return send_from_directory(avatars_dir, filename)

@app.route('/database/posts/<filename>')
def serve_post_image(filename):
    """Serve post images from database/posts folder"""
    posts_dir = os.path.join('database', 'posts')
    return send_from_directory(posts_dir, filename)

@app.route('/database/reels/<filename>')
def serve_reel_media(filename):
    """Serve reel media (videos/images) from database/reels folder"""
    reels_dir = os.path.join('database', 'reels')
    return send_from_directory(reels_dir, filename)

@app.route('/profile')
@app.route('/profile/<username>')
def profile(username=None):
    """Render profile page"""
    users = load_users()
    current_username = session.get('username')
    
    # If no username provided, show logged-in user's profile
    if not username:
        username = current_username
    
    # Find user by username
    user = None
    for u in users:
        if u['username'] == username:
            user = u
            break
    
    if not user:
        # Return 404 if user not found
        return "User not found", 404
    
    # Get user's posts - filter by user_id or username
    all_posts = load_posts()
    user_posts = [p for p in all_posts if p.get('user', {}).get('username') == username or p.get('username') == username]
    
    # Get saved posts - only show if viewing own profile
    saved_posts = []
    if username == current_username:
        saved_posts = [p for p in all_posts if p.get('is_saved', False)]
    
    # Check if viewing own profile
    is_own_profile = (username == current_username)
    
    return render_template('profile.html', 
                         user=user, 
                         user_posts=user_posts,
                         saved_posts=saved_posts,
                         is_own_profile=is_own_profile)

@app.route('/messages')
@login_required
def messages():
    """Render messages page - only show conversations for current user"""
    current_username = session.get('username')
    if not current_username:
        return redirect(url_for('login'))
    
    all_conversations = load_messages()
    # Filter conversations where current user is a participant
    # A user is a participant if:
    # 1. The conversation was created from their perspective (conv_username == current_username)
    # 2. OR they have sent messages in the conversation
    # 3. OR the other user has sent messages to them (even if they haven't replied yet)
    user_conversations = []
    for conv in all_conversations:
        is_participant = False
        conv_username = conv.get('user', {}).get('username')
        conv_messages = conv.get('messages', [])
        
        # Always ensure receiver info shows the OTHER user (not current user)
        other_user_username = None
        
        # Case 1: Current user is the "other" user in the conversation
        # This means someone started a conversation with current user
        if conv_username == current_username:
            is_participant = True
            # Need to find who the actual other user is (the one who created the conversation)
            # Look for the first message sender who is not the current user
            for message in conv_messages:
                sender = message.get('sender')
                if sender and sender != current_username:
                    other_user_username = sender
                    break
        else:
            # Case 2: Check if current user has sent any messages
            has_current_user_message = any(m.get('sender') == current_username for m in conv_messages)
            # Case 3: Check if the other user (conv_username) has sent any messages
            # This covers cases where someone messaged the current user but they haven't replied
            has_other_user_message = any(m.get('sender') == conv_username for m in conv_messages)
            # Case 4: Check if current user has received messages (any message not from current user)
            has_received_messages = any(m.get('sender') != current_username for m in conv_messages)
            
            # If current user sent messages OR other user sent messages OR there are any messages, include it
            if has_current_user_message or has_other_user_message or has_received_messages:
                is_participant = True
            
            # Set other_user_username for updating user info
            if conv_username and conv_username != current_username:
                other_user_username = conv_username
            else:
                # Find the other user from messages
                for message in conv_messages:
                    sender = message.get('sender')
                    if sender and sender != current_username:
                        other_user_username = sender
                        break
        
        # Update user info with the correct other user
        if other_user_username:
            other_user = get_user_by_username(other_user_username)
            if other_user:
                conv['user'] = {
                    'username': other_user.get('username'),
                    'full_name': other_user.get('full_name', other_user.get('username')),
                    'avatar': other_user.get('avatar', 'avatar-1.jpg'),
                }
        
        # Only include conversations that have actual messages from real users
        # Check that there are actual messages and they're not just placeholder messages
        has_real_messages = False
        if len(conv_messages) > 0:
            # Check if messages have actual content (not just "No messages yet" placeholder)
            for msg in conv_messages:
                msg_text = msg.get('text', '').strip()
                if msg_text and msg_text.lower() != 'no messages yet':
                    has_real_messages = True
                    break
        
        if is_participant and has_real_messages:
            # Set last_message from the actual last message in messages array
            if conv_messages and len(conv_messages) > 0:
                last_msg = conv_messages[-1]
                conv['last_message'] = {
                    'text': last_msg.get('text', ''),
                    'timestamp': last_msg.get('timestamp', ''),
                    'sender': last_msg.get('sender', '')
                }
            elif not conv.get('last_message'):
                conv['last_message'] = {'text': '', 'timestamp': '', 'sender': ''}
            
            user_conversations.append(conv)
    
    # Sort conversations by last message timestamp (most recent first)
    def get_last_message_time(conv):
        messages = conv.get('messages', [])
        if not messages:
            return 0
        # Try to parse timestamp or use a default
        last_msg = messages[-1]
        timestamp = last_msg.get('timestamp', '')
        # For now, just return message ID as proxy for time (higher ID = more recent)
        return last_msg.get('id', 0)
    
    user_conversations.sort(key=get_last_message_time, reverse=True)
    
    return render_template('messages.html', conversations=user_conversations, current_username=current_username)

def get_user_groups_optimized(all_groups, current_username, include_messages=False):
    """
    Optimized function to filter and process user groups.
    Only processes what's needed for display, avoiding redundant operations.
    
    Args:
        all_groups: List of all groups from database
        current_username: Username of current user
        include_messages: If True, includes full messages array (default: False for list view)
    """
    user_groups = []
    
    for group in all_groups:
        # Fast membership check - check admin first (most common case)
        is_member = False
        if group.get('admin') == current_username:
            is_member = True
        elif group.get('members'):
            # Optimized membership check with early exit
            members = group['members']
            # Check if username exists in members (faster than any() with generator)
            for member in members:
                if member.get('username') == current_username:
                    is_member = True
                    break
        
        if not is_member:
            continue
        
        # Create a lightweight copy for processing (don't include messages array by default)
        processed_group = {
            'id': group.get('id'),
            'name': group.get('name', ''),
            'description': group.get('description', ''),
            'avatar': group.get('avatar', 'group-1.jpg'),
            'cover_image': group.get('cover_image', ''),
            'members_count': group.get('members_count', 0),
            'category': group.get('category', 'other'),
            'privacy': group.get('privacy', 'Public'),
            'admin': group.get('admin', ''),
            'created_at': group.get('created_at', ''),
            'members': group.get('members', []),  # Include members for UI
            'is_member': True,
            'unread_count': 0,
            'last_message': {'text': '', 'timestamp': '', 'sender': '', 'sender_name': ''}
        }
        
        # Only include messages if explicitly requested (for detail view)
        if include_messages:
            processed_group['messages'] = group.get('messages', [])
        
        # Optimize message processing - only get last message, don't process all messages
        group_messages = group.get('messages', [])
        if group_messages:
            # Get last message efficiently (access last element directly)
            last_msg = group_messages[-1]
            msg_text = last_msg.get('text', '')
            # Truncate for preview (avoid sending long messages in list view)
            processed_group['last_message'] = {
                'text': msg_text[:50] + ('...' if len(msg_text) > 50 else ''),  # Truncate for preview
                'timestamp': last_msg.get('timestamp', ''),
                'sender': last_msg.get('sender', ''),
                'sender_name': last_msg.get('sender_name', last_msg.get('sender', ''))
            }
            
            # Calculate unread count efficiently
            # KEY RULE: If the last message was sent by the current user, their unread_count should be 0
            # Only count unread messages from others that came BEFORE or AFTER the user's last sent message
            last_message_sender = last_msg.get('sender', '')
            
            # If current user sent the last message, they should see 0 unread notifications
            if last_message_sender == current_username:
                processed_group['unread_count'] = 0
            else:
                # Count unread messages from others
                # Only iterate through messages once
                unread_count = 0
                for msg in group_messages:
                    # Check if message is unread and from someone else
                    if (msg.get('sender') != current_username and 
                        not msg.get('is_read', False)):
                        unread_count += 1
                processed_group['unread_count'] = unread_count
            
            # Store last message ID for sorting (don't need full messages array)
            processed_group['_sort_key'] = last_msg.get('id', 0)
        else:
            processed_group['_sort_key'] = 0
        
        user_groups.append(processed_group)
    
    # Sort by last message ID (most recent first) - using pre-calculated sort key
    user_groups.sort(key=lambda g: g.get('_sort_key', 0), reverse=True)
    
    # Remove internal sort key before returning
    for group in user_groups:
        group.pop('_sort_key', None)
    
    return user_groups

def get_group_by_id_optimized(group_id, current_username=None):
    """
    Optimized function to get a single group by ID.
    Loads groups once and returns only the requested group with minimal processing.
    
    Args:
        group_id: ID of the group to retrieve
        current_username: Optional username for membership check
    """
    groups = load_groups()
    group = next((g for g in groups if g.get('id') == group_id), None)
    
    if not group:
        return None
    
    # If username provided, check membership and add flags
    if current_username:
        is_member = False
        is_admin = False
        
        if group.get('admin') == current_username:
            is_member = True
            is_admin = True
        elif group.get('members'):
            member = next((m for m in group['members'] if m.get('username') == current_username), None)
            if member:
                is_member = True
                is_admin = member.get('is_admin', False)
        
        group['is_member'] = is_member
        group['is_admin'] = is_admin
    
    return group

@app.route('/groups')
@login_required
def groups():
    """Render groups page - only show groups where current user is a member"""
    current_username = session.get('username')
    if not current_username:
        return redirect(url_for('login'))
    
    # Load groups once
    all_groups = load_groups()
    
    # Optimized processing - only process user groups (don't include full messages for list view)
    user_groups = get_user_groups_optimized(all_groups, current_username, include_messages=False)
    
    # Get categories efficiently (cached if possible, or load once)
    categories = get_group_categories()
    
    return render_template('groups_new.html', 
                         groups=user_groups, 
                         categories=categories, 
                         get_category_icon=get_category_icon, 
                         current_username=current_username)

@app.route('/groups/<int:group_id>')
@login_required
def group_detail(group_id):
    """Render group detail page - optimized for fast loading"""
    current_username = session.get('username')
    if not current_username:
        return redirect(url_for('login'))
    
    # Use optimized function to get group
    group = get_group_by_id_optimized(group_id, current_username)
    
    if not group:
        flash('Group not found', 'error')
        return redirect(url_for('groups'))
    
    if not group.get('is_member', False):
        flash('You are not a member of this group', 'error')
        return redirect(url_for('groups'))
    
    # Don't include full messages array in template - messages loaded via API when needed
    # Create a lightweight copy without messages for template rendering
    group_lightweight = {
        'id': group.get('id'),
        'name': group.get('name', ''),
        'description': group.get('description', ''),
        'avatar': group.get('avatar', 'group-1.jpg'),
        'cover_image': group.get('cover_image', ''),
        'members_count': group.get('members_count', 0),
        'category': group.get('category', 'other'),
        'privacy': group.get('privacy', 'Public'),
        'admin': group.get('admin', ''),
        'created_at': group.get('created_at', ''),
        'members': group.get('members', []),
        'is_member': group.get('is_member', False),
        'is_admin': group.get('is_admin', False)
    }
    
    return render_template('groups.html', group=group_lightweight, current_username=current_username)

@app.route('/settings')
def settings():
    """Render settings page"""
    settings = load_settings()
    return render_template('settings.html', settings=settings)

# ==================== New API Endpoints ====================

@app.route('/api/reels')
def api_reels():
    """API endpoint to get all reels"""
    reels = load_reels()
    return jsonify(reels)

@app.route('/api/users')
def api_users():
    """API endpoint to get all users"""
    users = load_users()
    return jsonify(users)

@app.route('/api/users/<username>')
def api_user(username):
    """API endpoint to get a specific user"""
    try:
        users = load_users()
        user = None
        for u in users:
            if u.get('username') == username:
                user = u
                break
        
        if user:
            return jsonify(user)
        else:
            return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        print(f"Error in api_user: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/reels/<int:reel_id>/like', methods=['POST'])
def toggle_reel_like(reel_id):
    """Toggle like status for a reel"""
    reels = load_reels()
    target_reel = None
    
    for reel in reels:
        if reel['id'] == reel_id:
            target_reel = reel
            # Toggle like status
            reel['is_liked'] = not reel.get('is_liked', False)
            # Update like count
            if reel['is_liked']:
                reel['likes_count'] = reel.get('likes_count', 0) + 1
            else:
                reel['likes_count'] = max(0, reel.get('likes_count', 0) - 1)
            break
    
    if target_reel:
        save_reels(reels)
        return jsonify({
            'success': True, 
            'is_liked': target_reel.get('is_liked', False),
            'likes_count': target_reel.get('likes_count', 0)
        })
    else:
        return jsonify({'success': False, 'error': 'Reel not found'}), 404

@app.route('/api/reels/<int:reel_id>/save', methods=['POST'])
def toggle_reel_save(reel_id):
    """Toggle save status for a reel"""
    reels = load_reels()
    target_reel = None
    
    for reel in reels:
        if reel['id'] == reel_id:
            target_reel = reel
            reel['is_saved'] = not reel.get('is_saved', False)
            break
    
    if target_reel:
        save_reels(reels)
        return jsonify({'success': True, 'is_saved': target_reel.get('is_saved', False)})
    else:
        return jsonify({'success': False, 'error': 'Reel not found'}), 404

@app.route('/api/reels/<int:reel_id>/follow', methods=['POST'])
def toggle_reel_follow(reel_id):
    """Toggle follow status for a reel creator"""
    reels = load_reels()
    target_reel = None
    
    for reel in reels:
        if reel['id'] == reel_id:
            target_reel = reel
            # Toggle follow status (stored per reel for now)
            reel['is_following'] = not reel.get('is_following', False)
            break
    
    if target_reel:
        save_reels(reels)
        return jsonify({'success': True, 'is_following': target_reel.get('is_following', False)})
    else:
        return jsonify({'success': False, 'error': 'Reel not found'}), 404

@app.route('/api/reels/<int:reel_id>/comments', methods=['GET'])
def get_reel_comments(reel_id):
    """Get comments for a reel"""
    reels = load_reels()
    target_reel = None
    
    for reel in reels:
        if reel['id'] == reel_id:
            target_reel = reel
            break
    
    if target_reel:
        comments = target_reel.get('comments', [])
        return jsonify({'success': True, 'comments': comments})
    else:
        return jsonify({'success': False, 'error': 'Reel not found'}), 404

@app.route('/api/reels/<int:reel_id>/comments', methods=['POST'])
def post_reel_comment(reel_id):
    """Post a comment on a reel"""
    reels = load_reels()
    target_reel = None
    
    data = request.get_json()
    comment_text = data.get('text', '').strip()
    
    if not comment_text:
        return jsonify({'success': False, 'error': 'Comment text is required'}), 400
    
    for reel in reels:
        if reel['id'] == reel_id:
            target_reel = reel
            # Initialize comments array if it doesn't exist
            if 'comments' not in reel:
                reel['comments'] = []
            
            # Add new comment
            new_comment = {
                'id': len(reel['comments']) + 1,
                'username': 'current_user',  # In production, get from session
                'text': comment_text,
                'time_ago': 'Just now',
                'avatar': 'avatar-2.jpg'
            }
            reel['comments'].append(new_comment)
            
            # Update comment count
            reel['comments_count'] = len(reel['comments'])
            break
    
    if target_reel:
        save_reels(reels)
        return jsonify({'success': True, 'comment': new_comment})
    else:
        return jsonify({'success': False, 'error': 'Reel not found'}), 404

@app.route('/api/messages')
@login_required
def api_messages():
    """
    SECURE API endpoint to get all conversations for current user.
    Uses secure authorization checks and validates all data.
    """
    current_username = session.get('username')
    if not current_username or not validate_username(current_username):
        return jsonify({'error': 'Unauthorized'}), 401
    
    all_conversations = load_messages()
    user_conversations = []
    
    for conv in all_conversations:
        # Use secure function to check if user is in conversation
        if not is_user_in_conversation(conv, current_username):
            continue
        
        # Only include conversations with real messages
        conv_messages = conv.get('messages', [])
        has_real_messages = False
        if len(conv_messages) > 0:
            for msg in conv_messages:
                msg_text = msg.get('text', '').strip()
                # Remove HTML tags to check actual content
                if msg_text and msg_text.lower() not in ['no messages yet', '']:
                    has_real_messages = True
                    break
        
        if not has_real_messages:
            continue
        
        # Always ensure receiver info shows the OTHER user (not current user)
        conv_username = conv.get('user', {}).get('username')
        other_user_username = None
        
        # If the conversation user is current user, find the actual other user from messages
        if conv_username == current_username:
            for message in conv_messages:
                sender = message.get('sender')
                if sender and sender != current_username and validate_username(sender):
                    other_user_username = sender
                    break
        # Otherwise, verify the conversation user is not current user and find from messages if needed
        else:
            if conv_username and conv_username != current_username:
                # Verify this user actually exists and has sent/received messages
                other_user_username = conv_username
            else:
                # Find the other user from messages
                for message in conv_messages:
                    sender = message.get('sender')
                    if sender and sender != current_username and validate_username(sender):
                        other_user_username = sender
                        break
        
        # Update user info with the correct other user
        if other_user_username:
            other_user = get_user_by_username(other_user_username)
            if other_user:
                conv['user'] = {
                    'username': other_user.get('username'),
                    'full_name': other_user.get('full_name', other_user.get('username')),
                    'avatar': other_user.get('avatar', 'avatar-1.jpg')
                }
        
        # Set last_message from the actual last message in messages array
        if conv_messages and len(conv_messages) > 0:
            last_msg = conv_messages[-1]
            conv['last_message'] = {
                'text': last_msg.get('text', ''),
                'timestamp': last_msg.get('timestamp', ''),
                'sender': last_msg.get('sender', '')
            }
        elif not conv.get('last_message'):
            conv['last_message'] = {'text': '', 'timestamp': '', 'sender': ''}
        
        # Calculate unread_count from current user's perspective (only messages received, not sent)
        unread_count = sum(1 for m in conv_messages 
                          if m.get('sender') != current_username and not m.get('is_read', False))
        conv['unread_count'] = unread_count
        
        user_conversations.append(conv)
    
    # Sort by last message ID (most recent first)
    def get_last_message_id(conv):
        messages = conv.get('messages', [])
        if not messages:
            return 0
        return messages[-1].get('id', 0) if messages else 0
    
    user_conversations.sort(key=get_last_message_id, reverse=True)
    
    return jsonify(user_conversations)

@app.route('/api/messages/search', methods=['GET'])
@login_required
def search_messages():
    """
    SECURE API endpoint to search conversations and messages.
    Searches in conversation names and message content.
    """
    current_username = session.get('username')
    if not current_username or not validate_username(current_username):
        return jsonify({'error': 'Unauthorized'}), 401
    
    query = request.args.get('q', '').strip().lower()
    if not query:
        return jsonify({'conversations': [], 'messages': []})
    
    all_conversations = load_messages()
    matched_conversations = []
    matched_messages = {}
    
    for conv in all_conversations:
        # Check if user has access to this conversation
        if not is_user_in_conversation(conv, current_username):
            continue
        
        conv_username = conv.get('user', {}).get('username')
        conv_messages = conv.get('messages', [])
        
        # Always ensure receiver info shows the OTHER user (not current user)
        other_user_username = None
        if conv_username == current_username:
            for message in conv_messages:
                sender = message.get('sender')
                if sender and sender != current_username and validate_username(sender):
                    other_user_username = sender
                    break
        else:
            if conv_username and conv_username != current_username:
                other_user_username = conv_username
            else:
                for message in conv_messages:
                    sender = message.get('sender')
                    if sender and sender != current_username and validate_username(sender):
                        other_user_username = sender
                        break
        
        # Set display user to the correct other user
        display_user = conv.get('user', {})
        if other_user_username:
            other_user = get_user_by_username(other_user_username)
            if other_user:
                display_user = {
                    'username': other_user.get('username'),
                    'full_name': other_user.get('full_name', other_user.get('username')),
                    'avatar': other_user.get('avatar', 'avatar-1.jpg')
                }
        
        # Search in user name
        user_name = display_user.get('full_name', '').lower()
        username = display_user.get('username', '').lower()
        matches_name = query in user_name or query in username
        
        # Search in messages
        matching_messages = []
        for msg in conv_messages:
            msg_text = msg.get('text', '').lower()
            if query in msg_text:
                matching_messages.append(msg)
        
        # If matches name or has matching messages, include conversation
        if matches_name or matching_messages:
            conv_copy = conv.copy()
            conv_copy['user'] = display_user
            
            # Set last_message from the actual last message in messages array
            if conv_messages and len(conv_messages) > 0:
                last_msg = conv_messages[-1]
                conv_copy['last_message'] = {
                    'text': last_msg.get('text', ''),
                    'timestamp': last_msg.get('timestamp', ''),
                    'sender': last_msg.get('sender', '')
                }
            elif not conv_copy.get('last_message'):
                conv_copy['last_message'] = {'text': '', 'timestamp': '', 'sender': ''}
            
            matched_conversations.append(conv_copy)
            
            if matching_messages:
                matched_messages[conv.get('id')] = matching_messages
    
    # Sort by last message ID
    def get_last_message_id(conv):
        messages = conv.get('messages', [])
        if not messages:
            return 0
        return messages[-1].get('id', 0) if messages else 0
    
    matched_conversations.sort(key=get_last_message_id, reverse=True)
    
    return jsonify({
        'conversations': matched_conversations,
        'messages': matched_messages
    })

@app.route('/api/messages/start/<username>', methods=['POST'])
@login_required
def start_conversation(username):
    """
    SECURE: Start a new conversation with a user.
    Validates username, checks authorization, and uses secure tokens.
    """
    current_username = session.get('username')
    if not current_username or not validate_username(current_username):
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Validate target username
    if not validate_username(username):
        return jsonify({'error': 'Invalid username format'}), 400
    
    # Can't start conversation with yourself
    if username == current_username:
        return jsonify({'error': 'Cannot start conversation with yourself'}), 400
    
    # Get user from database
    target_user = get_user_by_username(username)
    if not target_user:
        return jsonify({'error': 'User not found'}), 404
    
    conversations = load_messages()
    
    # Find existing conversation using secure check
    existing_conversation = None
    for conv in conversations:
        # Check if both users are in this conversation
        if is_user_in_conversation(conv, current_username) and is_user_in_conversation(conv, username):
            existing_conversation = conv
            break
    
    # If conversation exists, return it with secure tokens
    if existing_conversation:
        existing_conversation['user'] = {
            'username': target_user.get('username'),
            'full_name': target_user.get('full_name', target_user.get('username')),
            'avatar': target_user.get('avatar', 'avatar-1.jpg')
        }
        
        conversation_token = generate_conversation_token(
            existing_conversation.get('id'),
            current_username
        )
        username_token = generate_username_token(target_user.get('username'))
        
        return jsonify({
            'success': True,
            'conversation_id': existing_conversation.get('id'),
            'conversation': existing_conversation,
            'token': conversation_token,
            'username_token': username_token,
            'message': 'Conversation already exists'
        })
    
    # Create new conversation
    max_id = max([c.get('id', 0) for c in conversations], default=0)
    new_conversation_id = max_id + 1
    
    new_conversation = {
        'id': new_conversation_id,
        'user': {
            'username': target_user.get('username'),
            'full_name': target_user.get('full_name', target_user.get('username')),
            'avatar': target_user.get('avatar', 'avatar-1.jpg')
        },
        'last_message': {
            'text': 'No messages yet',
            'timestamp': 'Just now',
            'is_read': True,
            'sender': current_username
        },
        'unread_count': 0,
        'messages': []
    }
    
    conversations.append(new_conversation)
    
    if save_messages(conversations):
        conversation_token = generate_conversation_token(new_conversation_id, current_username)
        username_token = generate_username_token(target_user.get('username'))
        
        return jsonify({
            'success': True,
            'conversation_id': new_conversation_id,
            'conversation': new_conversation,
            'token': conversation_token,
            'username_token': username_token
        })
    else:
        return jsonify({'error': 'Failed to create conversation'}), 500

@app.route('/api/messages/find/<username>', methods=['GET'])
@login_required
def find_conversation_by_username(username):
    """
    SECURE: Find a conversation with a specific user by username.
    Validates username and uses secure authorization checks.
    """
    current_username = session.get('username')
    if not current_username or not validate_username(current_username):
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Validate target username
    if not validate_username(username):
        return jsonify({'error': 'Invalid username format'}), 400
    
    # Can't find conversation with yourself
    if username == current_username:
        return jsonify({'error': 'Cannot find conversation with yourself'}), 400
    
    # Get user from database
    target_user = get_user_by_username(username)
    if not target_user:
        return jsonify({'error': 'User not found'}), 404
    
    conversations = load_messages()
    
    # Find existing conversation using secure check
    existing_conversation = None
    for conv in conversations:
        if is_user_in_conversation(conv, current_username) and is_user_in_conversation(conv, username):
            existing_conversation = conv
            break
    
    if existing_conversation:
        existing_conversation['user'] = {
            'username': target_user.get('username'),
            'full_name': target_user.get('full_name', target_user.get('username')),
            'avatar': target_user.get('avatar', 'avatar-1.jpg')
        }
        
        conversation_token = generate_conversation_token(
            existing_conversation.get('id'),
            current_username
        )
        username_token = generate_username_token(target_user.get('username'))
        
        return jsonify({
            'success': True,
            'conversation': existing_conversation,
            'conversation_id': existing_conversation.get('id'),
            'token': conversation_token,
            'username_token': username_token
        })
    else:
        return jsonify({
            'success': False,
            'message': 'No conversation found'
        }), 404

@app.route('/api/messages/token/<token>', methods=['GET'])
@login_required
def get_conversation_by_token(token):
    """
    SECURE: Get conversation details using encrypted token.
    Validates token and ensures user has access to the conversation.
    """
    current_username = session.get('username')
    if not current_username or not validate_username(current_username):
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Validate token
    token_data = validate_conversation_token(token)
    if not token_data:
        return jsonify({'error': 'Invalid or expired token'}), 403
    
    # Verify the token is for the current user
    if token_data.get('username') != current_username:
        return jsonify({'error': 'Token does not match current user'}), 403
    
    conversation_id = token_data.get('conversation_id')
    if not conversation_id or not isinstance(conversation_id, int):
        return jsonify({'error': 'Invalid token data'}), 400
    
    # Get conversation
    conversations = load_messages()
    conversation = next((c for c in conversations if c.get('id') == conversation_id), None)
    
    if not conversation:
        return jsonify({'error': 'Conversation not found'}), 404
    
    # SECURE: Use secure function to check authorization
    if not is_user_in_conversation(conversation, current_username):
        return jsonify({'error': 'Access denied'}), 403
    
    # Enrich messages with sender avatar information
    enriched_messages = []
    for message in conversation.get('messages', []):
        enriched_message = message.copy()
        if 'sender_avatar' not in enriched_message or not enriched_message.get('sender_avatar'):
            sender_username = enriched_message.get('sender')
            if sender_username and validate_username(sender_username):
                sender_user = get_user_by_username(sender_username)
                if sender_user:
                    enriched_message['sender_avatar'] = sender_user.get('avatar', 'avatar-1.jpg')
                    enriched_message['sender_full_name'] = sender_user.get('full_name', sender_username)
                else:
                    enriched_message['sender_avatar'] = 'avatar-1.jpg'
                    enriched_message['sender_full_name'] = sender_username
        enriched_messages.append(enriched_message)
    
    conversation_copy = conversation.copy()
    conversation_copy['messages'] = enriched_messages
    
    return jsonify({
        'conversation': conversation_copy,
        'messages': enriched_messages
    })

@app.route('/api/messages/username-token/<token>', methods=['GET'])
@login_required
def get_conversation_by_username_token(token):
    """
    SECURE: Get or create conversation using encrypted username token.
    Validates token and uses secure authorization checks.
    """
    current_username = session.get('username')
    if not current_username or not validate_username(current_username):
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Validate token
    token_data = validate_username_token(token)
    if not token_data:
        return jsonify({'error': 'Invalid or expired token'}), 403
    
    username = token_data.get('username')
    if not username or not validate_username(username) or username == current_username:
        return jsonify({'error': 'Invalid token data'}), 400
    
    # Get user from database
    target_user = get_user_by_username(username)
    if not target_user:
        return jsonify({'error': 'User not found'}), 404
    
    conversations = load_messages()
    
    # Find existing conversation using secure check
    existing_conversation = None
    for conv in conversations:
        if is_user_in_conversation(conv, current_username) and is_user_in_conversation(conv, username):
            existing_conversation = conv
            break
    
    if existing_conversation:
        existing_conversation['user'] = {
            'username': target_user.get('username'),
            'full_name': target_user.get('full_name', target_user.get('username')),
            'avatar': target_user.get('avatar', 'avatar-1.jpg')
        }
        
        conversation_token = generate_conversation_token(
            existing_conversation.get('id'),
            current_username
        )
        
        # Enrich messages
        enriched_messages = []
        for message in existing_conversation.get('messages', []):
            enriched_message = message.copy()
            if 'sender_avatar' not in enriched_message or not enriched_message.get('sender_avatar'):
                sender_username = enriched_message.get('sender')
                if sender_username and validate_username(sender_username):
                    sender_user = get_user_by_username(sender_username)
                    if sender_user:
                        enriched_message['sender_avatar'] = sender_user.get('avatar', 'avatar-1.jpg')
                        enriched_message['sender_full_name'] = sender_user.get('full_name', sender_username)
                    else:
                        enriched_message['sender_avatar'] = 'avatar-1.jpg'
                        enriched_message['sender_full_name'] = sender_username
            enriched_messages.append(enriched_message)
        
        existing_conversation['messages'] = enriched_messages
        
        return jsonify({
            'success': True,
            'conversation': existing_conversation,
            'conversation_id': existing_conversation.get('id'),
            'token': conversation_token
        })
    else:
        # Create new conversation
        max_id = max([c.get('id', 0) for c in conversations], default=0)
        new_conversation_id = max_id + 1
        
        new_conversation = {
            'id': new_conversation_id,
            'user': {
                'username': target_user.get('username'),
                'full_name': target_user.get('full_name', target_user.get('username')),
                'avatar': target_user.get('avatar', 'avatar-1.jpg')
            },
            'last_message': {
                'text': 'No messages yet',
                'timestamp': 'Just now',
                'is_read': True,
                'sender': current_username
            },
            'unread_count': 0,
            'messages': []
        }
        
        conversations.append(new_conversation)
        
        if save_messages(conversations):
            conversation_token = generate_conversation_token(new_conversation_id, current_username)
            return jsonify({
                'success': True,
                'conversation': new_conversation,
                'conversation_id': new_conversation_id,
                'token': conversation_token
            })
        else:
            return jsonify({'error': 'Failed to create conversation'}), 500

@app.route('/api/messages/<int:conversation_id>', methods=['GET'])
@login_required
def get_conversation_messages(conversation_id):
    """
    SECURE: Get all messages for a specific conversation.
    Validates conversation ID and ensures user has access.
    """
    current_username = session.get('username')
    if not current_username or not validate_username(current_username):
        return jsonify({'error': 'Unauthorized'}), 401
    
    if not isinstance(conversation_id, int) or conversation_id < 1:
        return jsonify({'error': 'Invalid conversation ID'}), 400
    
    conversations = load_messages()
    conversation = next((c for c in conversations if c.get('id') == conversation_id), None)
    
    if not conversation:
        return jsonify({'error': 'Conversation not found'}), 404
    
    # SECURE: Use secure function to check authorization
    if not is_user_in_conversation(conversation, current_username):
        return jsonify({'error': 'Access denied'}), 403
    
    # Enrich messages with sender avatar information
    enriched_messages = []
    for message in conversation.get('messages', []):
        enriched_message = message.copy()
        if 'sender_avatar' not in enriched_message or not enriched_message.get('sender_avatar'):
            sender_username = enriched_message.get('sender')
            if sender_username and validate_username(sender_username):
                sender_user = get_user_by_username(sender_username)
                if sender_user:
                    enriched_message['sender_avatar'] = sender_user.get('avatar', 'avatar-1.jpg')
                    enriched_message['sender_full_name'] = sender_user.get('full_name', sender_username)
                else:
                    enriched_message['sender_avatar'] = 'avatar-1.jpg'
                    enriched_message['sender_full_name'] = sender_username
        enriched_messages.append(enriched_message)
    
    conversation_copy = conversation.copy()
    conversation_copy['messages'] = enriched_messages
    
    
    return jsonify({
        'conversation': conversation_copy,
        'messages': enriched_messages
    })

@app.route('/api/messages/<int:conversation_id>/send', methods=['POST'])
@login_required
def send_message(conversation_id):
    """
    SECURE: Send a message to a conversation.
    Includes rate limiting, input sanitization, XSS protection, and authorization checks.
    """
    current_username = session.get('username')
    if not current_username or not validate_username(current_username):
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Validate conversation ID
    if not isinstance(conversation_id, int) or conversation_id < 1:
        return jsonify({'error': 'Invalid conversation ID'}), 400
    
    # SECURE: Check rate limiting
    allowed, error_msg = check_rate_limit(current_username)
    if not allowed:
        return jsonify({'error': error_msg}), 429  # 429 = Too Many Requests
    
    # Get and validate message text
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request data'}), 400
    
    message_text = data.get('text', '')
    if not isinstance(message_text, str):
        return jsonify({'error': 'Message text must be a string'}), 400
    
    # SECURE: Sanitize message text (prevents XSS, validates input)
    message_text = sanitize_message_text(message_text)
    
    if not message_text or message_text.strip() == '':
        return jsonify({'error': 'Message text is required'}), 400
    
    # Load conversations
    conversations = load_messages()
    conversation = next((c for c in conversations if c.get('id') == conversation_id), None)
    
    if not conversation:
        return jsonify({'error': 'Conversation not found'}), 404
    
    # SECURE: Verify user is part of this conversation
    if not is_user_in_conversation(conversation, current_username):
        return jsonify({'error': 'Access denied'}), 403
    
    # Generate new message ID
    existing_messages = conversation.get('messages', [])
    new_message_id = max([m.get('id', 0) for m in existing_messages], default=0) + 1
    
    # Get current user's info
    current_user = get_user_by_username(current_username)
    sender_avatar = current_user.get('avatar', 'avatar-1.jpg') if current_user else 'avatar-1.jpg'
    sender_full_name = current_user.get('full_name', current_username) if current_user else current_username
    
    # Check for reply_to
    reply_to_data = data.get('reply_to')
    reply_to = None
    if reply_to_data and isinstance(reply_to_data, dict):
        reply_to_id = reply_to_data.get('id')
        reply_to_sender = reply_to_data.get('sender', '')
        reply_to_text = reply_to_data.get('text', '')
        
        # Validate that the replied-to message exists in the conversation
        if reply_to_id:
            replied_message = next((m for m in existing_messages if m.get('id') == reply_to_id), None)
            if replied_message:
                reply_to = {
                    'id': reply_to_id,
                    'sender': reply_to_sender or replied_message.get('sender', ''),
                    'text': reply_to_text or replied_message.get('text', '')
                }
    
    # Create new message (text is already sanitized)
    new_message = {
        'id': new_message_id,
        'sender': current_username,
        'sender_avatar': sender_avatar,
        'sender_full_name': sender_full_name,
        'text': message_text,  # Already sanitized
        'timestamp': datetime.now().strftime('%H:%M'),
        'is_read': False
    }
    
    # Add reply_to if present
    if reply_to:
        new_message['reply_to'] = reply_to
        
        # Create notification for the user whose message was replied to
        replied_to_username = reply_to.get('sender', '')
        if replied_to_username and replied_to_username != current_username:
            # Create reply notification
            notifications = load_notifications()
            notification_id = max([n.get('id', 0) for n in notifications], default=0) + 1
            
            # Get sender info for notification
            sender_user = get_user_by_username(current_username)
            sender_avatar_notif = sender_user.get('avatar', 'avatar-1.jpg') if sender_user else 'avatar-1.jpg'
            
            reply_notification = {
                'id': notification_id,
                'type': 'message_reply',
                'user': current_username,
                'target_user': replied_to_username,  # User who should receive this notification
                'avatar': sender_avatar_notif,
                'conversation_id': conversation_id,
                'message_id': new_message_id,
                'replied_to_message_id': reply_to.get('id'),
                'time_ago': 'Just now',
                'is_read': False,
                'action_text': f'replied to your message'
            }
            notifications.insert(0, reply_notification)
            save_notifications(notifications)
    
    # Add message to conversation
    conversation['messages'].append(new_message)
    
    # Update last message (preview - truncate if too long)
    preview_text = message_text[:50] + '...' if len(message_text) > 50 else message_text
    conversation['last_message'] = {
        'text': preview_text,
        'timestamp': datetime.now().strftime('%H:%M'),
        'is_read': False,
        'sender': current_username
    }
    
    # Update unread count for the other user
    other_username = conversation.get('user', {}).get('username')
    if other_username != current_username:
        conversation['unread_count'] = conversation.get('unread_count', 0) + 1
    
    # Save to database (save_messages will validate and sanitize again)
    if save_messages(conversations):
        return jsonify({
            'success': True,
            'message': new_message
        })
    else:
        return jsonify({'error': 'Failed to save message'}), 500

@app.route('/api/messages/<int:conversation_id>/poll', methods=['GET'])
@login_required
def poll_messages(conversation_id):
    """
    SECURE: Poll for new messages in a conversation (real-time updates).
    Validates conversation ID and ensures user has access.
    """
    current_username = session.get('username')
    if not current_username or not validate_username(current_username):
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Validate conversation ID
    if not isinstance(conversation_id, int) or conversation_id < 1:
        return jsonify({'error': 'Invalid conversation ID'}), 400
    
    # Get last message ID from query parameter (validate it's an integer)
    last_message_id = request.args.get('last_message_id', type=int)
    if last_message_id is not None and (not isinstance(last_message_id, int) or last_message_id < 0):
        last_message_id = None
    
    conversations = load_messages()
    conversation = next((c for c in conversations if c.get('id') == conversation_id), None)
    
    if not conversation:
        return jsonify({'error': 'Conversation not found'}), 404
    
    # SECURE: Verify user is part of this conversation
    if not is_user_in_conversation(conversation, current_username):
        return jsonify({'error': 'Access denied'}), 403
    
    # Get new messages since last_message_id
    all_messages = conversation.get('messages', [])
    if last_message_id:
        new_messages = [m for m in all_messages if m.get('id', 0) > last_message_id]
    else:
        new_messages = all_messages
    
    # Enrich new messages with sender avatar information
    enriched_new_messages = []
    for message in new_messages:
        enriched_message = message.copy()
        if 'sender_avatar' not in enriched_message or not enriched_message.get('sender_avatar'):
            sender_username = enriched_message.get('sender')
            if sender_username and validate_username(sender_username):
                sender_user = get_user_by_username(sender_username)
                if sender_user:
                    enriched_message['sender_avatar'] = sender_user.get('avatar', 'avatar-1.jpg')
                    enriched_message['sender_full_name'] = sender_user.get('full_name', sender_username)
                else:
                    enriched_message['sender_avatar'] = 'avatar-1.jpg'
                    enriched_message['sender_full_name'] = sender_username
        enriched_new_messages.append(enriched_message)
    
    # Mark messages as read if they're from the other user
    updated = False
    for message in enriched_new_messages:
        if message.get('sender') != current_username and not message.get('is_read', False):
            message['is_read'] = True
            updated = True
    
    # Update unread count
    if updated:
        unread_count = sum(1 for m in all_messages 
                          if m.get('sender') != current_username and not m.get('is_read', False))
        conversation['unread_count'] = unread_count
        save_messages(conversations)  # Save updated read status
    
    return jsonify({
        'new_messages': enriched_new_messages,
        'last_message_id': max([m.get('id', 0) for m in all_messages], default=0),
        'unread_count': conversation.get('unread_count', 0)
    })

@app.route('/api/messages/<int:conversation_id>/mark-read', methods=['POST'])
@login_required
def mark_conversation_read(conversation_id):
    """
    SECURE: Mark all messages in a conversation as read for the current user.
    """
    current_username = session.get('username')
    if not current_username or not validate_username(current_username):
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Validate conversation ID
    if not isinstance(conversation_id, int) or conversation_id < 1:
        return jsonify({'error': 'Invalid conversation ID'}), 400
    
    conversations = load_messages()
    conversation = next((c for c in conversations if c.get('id') == conversation_id), None)
    
    if not conversation:
        return jsonify({'error': 'Conversation not found'}), 404
    
    # SECURE: Verify user is part of this conversation
    if not is_user_in_conversation(conversation, current_username):
        return jsonify({'error': 'Access denied'}), 403
    
    # Mark all messages from other users as read
    all_messages = conversation.get('messages', [])
    updated = False
    for message in all_messages:
        if message.get('sender') != current_username and not message.get('is_read', False):
            message['is_read'] = True
            updated = True
    
    # Update unread count
    if updated:
        unread_count = sum(1 for m in all_messages 
                          if m.get('sender') != current_username and not m.get('is_read', False))
        conversation['unread_count'] = unread_count
        
        if save_messages(conversations):
            return jsonify({
                'success': True,
                'unread_count': unread_count
            })
        else:
            return jsonify({'error': 'Failed to save read status'}), 500
    
    return jsonify({
        'success': True,
        'unread_count': conversation.get('unread_count', 0)
    })

@app.route('/api/groups')
@login_required
def api_groups():
    """
    SECURE API endpoint to get all groups for current user.
    Only returns groups where user is a member.
    Optimized for fast loading.
    """
    current_username = session.get('username')
    if not current_username or not validate_username(current_username):
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Load groups once
    all_groups = load_groups()
    
    # Use optimized processing function (don't include full messages for list view)
    user_groups = get_user_groups_optimized(all_groups, current_username, include_messages=False)
    
    return jsonify(user_groups)

@app.route('/api/search')
def api_search():
    """Universal search endpoint - searches across all databases"""
    query = request.args.get('q', '').lower().strip()
    
    if not query:
        return jsonify({
            'results': {
                'users': [],
                'posts': [],
                'groups': [],
                'events': [],
                'messages': []
            },
            'total_results': 0
        })
    
    # Search across all databases
    results = {
        'users': [],
        'posts': [],
        'groups': [],
        'events': [],
        'messages': []
    }
    
    # Search Users
    users = load_users()
    for user in users:
        if (query in user.get('username', '').lower() or 
            query in user.get('full_name', '').lower() or 
            query in user.get('bio', '').lower()):
            results['users'].append(user)
    
    # Search Posts
    posts = load_posts()
    for post in posts:
        if (query in post.get('caption', '').lower() or 
            query in post.get('username', '').lower()):
            results['posts'].append(post)
    
    # Search Groups
    groups = load_groups()
    for group in groups:
        if (query in group.get('name', '').lower() or 
            query in group.get('description', '').lower() or 
            query in group.get('category', '').lower()):
            results['groups'].append(group)
    
    # Search Events - using correct field names and improved matching
    events = load_events()
    for event in events:
        # Search in title, description, location, category, and host
        if (query in event.get('title', '').lower() or 
            query in event.get('description', '').lower() or 
            query in event.get('location', '').lower() or
            query in event.get('category', '').lower() or
            query in event.get('host', '').lower() or
            query in event.get('host_username', '').lower()):
            results['events'].append(event)
    
    # Search Messages/Conversations
    conversations = load_messages()
    for conversation in conversations:
        user = conversation.get('user', {})
        if (query in user.get('username', '').lower() or 
            query in user.get('full_name', '').lower()):
            results['messages'].append(conversation)
        else:
            # Search in messages
            messages = conversation.get('messages', [])
            for message in messages:
                if query in message.get('text', '').lower():
                    results['messages'].append(conversation)
                    break
    
    # Calculate total results
    total_results = (len(results['users']) + len(results['posts']) + 
                    len(results['groups']) + len(results['events']) + 
                    len(results['messages']))
    
    return jsonify({
        'results': results,
        'total_results': total_results,
        'query': query
    })

@app.route('/api/shop/search')
def api_shop_search():
    """Shop products search endpoint"""
    from datetime import datetime
    query = request.args.get('q', '').strip().lower()
    
    products = load_shop()
    categories = get_shop_categories()
    
    # Calculate if product is new (created within last 7 days)
    current_date = datetime.now().date()
    today_str = datetime.now().strftime('%Y-%m-%d')
    
    for product in products:
        try:
            # Ensure created_at exists, default to today if missing
            if 'created_at' not in product or not product.get('created_at'):
                product['created_at'] = today_str
            
            created_date_str = product.get('created_at', '')
            if created_date_str:
                created_date = datetime.strptime(created_date_str, '%Y-%m-%d').date()
                days_old = (current_date - created_date).days
                # Mark as new if created within last 7 days
                product['is_new'] = days_old <= 7 and days_old >= 0
            else:
                # If still empty, mark as new (just created)
                product['is_new'] = True
        except Exception as e:
            print(f"Error calculating is_new for product {product.get('id')}: {e}")
            product['is_new'] = False
    
    # Filter products by search query if provided
    if query:
        filtered_products = []
        for product in products:
            # Search in product name, description, category, and seller
            product_name = product.get('name', '').lower()
            product_desc = product.get('description', '').lower()
            product_category = product.get('category', '').lower()
            product_seller = product.get('seller', '').lower()
            
            if (query in product_name or 
                query in product_desc or 
                query in product_category or 
                query in product_seller):
                filtered_products.append(product)
        products = filtered_products
    
    # Sort products: new products first, then by created date (newest first)
    def sort_key(product):
        # Return tuple: (not is_new, -days_old)
        # This ensures is_new=True products come first (False < True)
        # Within each group, sort by newest first
        is_new = product.get('is_new', False)
        try:
            created_date_str = product.get('created_at', today_str)
            created_date = datetime.strptime(created_date_str, '%Y-%m-%d').date()
            days_old = (current_date - created_date).days
        except:
            days_old = 0
        # Return (0 for new, 1 for old), (-days_old for reverse date sort)
        return (0 if is_new else 1, -days_old)
    
    products = sorted(products, key=sort_key)
    
    return jsonify({
        'products': products,
        'categories': categories,
        'total_results': len(products),
        'query': query
    })

@app.route('/api/groups', methods=['POST'])
def create_group():
    """Create a new group"""
    try:
        # Handle form data with file uploads
        avatar_filename = None
        cover_filename = None
        
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and file.filename and allowed_file(file.filename):
                # Generate unique filename
                filename = secure_filename(file.filename)
                file_extension = filename.rsplit('.', 1)[1].lower()
                unique_filename = f"group-{uuid.uuid4().hex}.{file_extension}"
                
                # Save to database/groups folder
                groups_folder = os.path.join('database', 'groups')
                os.makedirs(groups_folder, exist_ok=True)
                file_path = os.path.join(groups_folder, unique_filename)
                file.save(file_path)
                avatar_filename = unique_filename
        
        if 'cover' in request.files:
            file = request.files['cover']
            if file and file.filename and allowed_file(file.filename):
                # Generate unique filename
                filename = secure_filename(file.filename)
                file_extension = filename.rsplit('.', 1)[1].lower()
                unique_filename = f"group-cover-{uuid.uuid4().hex}.{file_extension}"
                
                # Save to database/groups folder
                groups_folder = os.path.join('database', 'groups')
                os.makedirs(groups_folder, exist_ok=True)
                file_path = os.path.join(groups_folder, unique_filename)
                file.save(file_path)
                cover_filename = unique_filename
        
        # Get form data
        data = {
            'name': request.form.get('name'),
            'description': request.form.get('description'),
            'category': request.form.get('category', 'other'),
            'privacy': request.form.get('privacy', 'Public')
        }
        
        # Validate required fields
        required_fields = ['name', 'description']
        for field in required_fields:
            if not data[field]:
                return jsonify({'success': False, 'error': f'Missing required field: {field}'}), 400
        
        # Load existing groups
        groups = load_groups()
        
        # Generate new group ID
        new_id = max([group.get('id', 0) for group in groups], default=0) + 1
        
        # Create new group
        new_group = {
            'id': new_id,
            'name': data['name'],
            'description': data['description'],
            'category': data['category'],
            'privacy': data['privacy'],
            'avatar': avatar_filename or 'group-1.jpg',  # Default avatar
            'cover_image': cover_filename or 'group-cover-1.jpg',  # Default cover
            'members_count': 1,  # Creator is the first member
            'is_member': True,
            'is_admin': True,
            'created_at': request.form.get('created_at', ''),
            'last_message': None,
            'unread_count': 0,
            'messages': []
        }
        
        # Add to groups list
        groups.append(new_group)
        
        # Save to database
        if save_groups(groups):
            return jsonify({'success': True, 'group': new_group}), 201
        else:
            return jsonify({'success': False, 'error': 'Failed to save group'}), 500
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/groups/<int:group_id>')
@login_required
def api_group(group_id):
    """SECURE API endpoint to get a specific group with messages - optimized for fast loading."""
    current_username = session.get('username')
    if not current_username or not validate_username(current_username):
        return jsonify({'error': 'Unauthorized'}), 401
    if not isinstance(group_id, int) or group_id < 1:
        return jsonify({'error': 'Invalid group ID'}), 400
    
    # Use optimized function to get group
    group = get_group_by_id_optimized(group_id, current_username)
    
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    
    if not group.get('is_member', False):
        return jsonify({'error': 'Access denied'}), 403
    
    # Get messages limit from query parameter (for pagination/lazy loading)
    limit = request.args.get('limit', type=int)
    offset = request.args.get('offset', type=int, default=0)
    
    # Get all messages
    all_messages = group.get('messages', [])
    total_messages = len(all_messages)
    
    # Apply pagination if limit is specified (optimize for large message lists)
    # For chat: show newest messages first, load older ones on scroll up
    if limit and limit > 0:
        # Calculate which messages to get (from the end, going backwards)
        # offset=0: get last 'limit' messages (newest)
        # offset=limit: get next 'limit' older messages
        start_idx = max(0, total_messages - offset - limit)
        end_idx = total_messages - offset
        messages_to_process = all_messages[start_idx:end_idx]
        # Don't reverse - keep chronological order (oldest to newest) for display
    else:
        messages_to_process = all_messages
    
    # Only enrich messages that will be returned (lazy enrichment)
    enriched_messages = []
    # Cache user data to avoid multiple lookups for same user
    user_cache = {}
    
    for message in messages_to_process:
        enriched_message = message.copy()
        # Only enrich if not already enriched
        if 'sender_avatar' not in enriched_message or not enriched_message.get('sender_avatar'):
            sender_username = enriched_message.get('sender')
            if sender_username and validate_username(sender_username):
                # Check cache first
                if sender_username not in user_cache:
                    sender_user = get_user_by_username(sender_username)
                    if sender_user:
                        user_cache[sender_username] = {
                            'avatar': sender_user.get('avatar', 'avatar-1.jpg'),
                            'full_name': sender_user.get('full_name', sender_username)
                        }
                    else:
                        user_cache[sender_username] = {
                            'avatar': 'avatar-1.jpg',
                            'full_name': sender_username
                        }
                
                cached_user = user_cache[sender_username]
                enriched_message['sender_avatar'] = cached_user['avatar']
                enriched_message['sender_full_name'] = cached_user['full_name']
        enriched_messages.append(enriched_message)
    
    # Create lightweight group copy (without full messages array if paginated)
    group_copy = {
        'id': group.get('id'),
        'name': group.get('name', ''),
        'description': group.get('description', ''),
        'avatar': group.get('avatar', 'group-1.jpg'),
        'cover_image': group.get('cover_image', ''),
        'members_count': group.get('members_count', 0),
        'category': group.get('category', 'other'),
        'privacy': group.get('privacy', 'Public'),
        'admin': group.get('admin', ''),
        'created_at': group.get('created_at', ''),
        'members': group.get('members', []),
        'is_member': group.get('is_member', False),
        'is_admin': group.get('is_admin', False)
    }
    
    # Add pagination info if limit was specified
    response_data = {
        'group': group_copy,
        'messages': enriched_messages,
        'total_messages': len(all_messages),
        'last_message_id': max([m.get('id', 0) for m in all_messages], default=0)
    }
    
    if limit:
        response_data['limit'] = limit
        response_data['offset'] = offset
        response_data['has_more'] = (offset + limit) < len(all_messages)
    
    return jsonify(response_data)

@app.route('/api/groups/<int:group_id>/send', methods=['POST'])
@login_required
def send_group_message(group_id):
    """SECURE: Send a message to a group - optimized for fast loading."""
    current_username = session.get('username')
    if not current_username or not validate_username(current_username):
        return jsonify({'error': 'Unauthorized'}), 401
    if not isinstance(group_id, int) or group_id < 1:
        return jsonify({'error': 'Invalid group ID'}), 400
    allowed, error_msg = check_rate_limit(current_username)
    if not allowed:
        return jsonify({'error': error_msg}), 429
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request data'}), 400
    message_text = data.get('text', '')
    if not isinstance(message_text, str):
        return jsonify({'error': 'Message text must be a string'}), 400
    message_text = sanitize_message_text(message_text)
    if not message_text or message_text.strip() == '':
        return jsonify({'error': 'Message text is required'}), 400
    
    # First check membership with optimized function (fast check)
    group_check = get_group_by_id_optimized(group_id, current_username)
    if not group_check:
        return jsonify({'error': 'Group not found'}), 404
    if not group_check.get('is_member', False):
        return jsonify({'error': 'Access denied'}), 403
    
    # Now load all groups for saving (we need the full list to save)
    groups = load_groups()
    group = next((g for g in groups if g.get('id') == group_id), None)
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    
    # Get existing messages efficiently (don't process all, just get max ID)
    existing_messages = group.get('messages', [])
    new_message_id = max([m.get('id', 0) for m in existing_messages], default=0) + 1
    
    # Get user info once
    current_user = get_user_by_username(current_username)
    sender_avatar = current_user.get('avatar', 'avatar-1.jpg') if current_user else 'avatar-1.jpg'
    sender_full_name = current_user.get('full_name', current_username) if current_user else current_username
    
    # Check for reply_to
    reply_to_data = data.get('reply_to')
    reply_to = None
    if reply_to_data and isinstance(reply_to_data, dict):
        reply_to_id = reply_to_data.get('id')
        reply_to_sender = reply_to_data.get('sender', '')
        reply_to_text = reply_to_data.get('text', '')
        
        # Validate that the replied-to message exists in the group
        if reply_to_id:
            replied_message = next((m for m in existing_messages if m.get('id') == reply_to_id), None)
            if replied_message:
                reply_to = {
                    'id': reply_to_id,
                    'sender': reply_to_sender or replied_message.get('sender', ''),
                    'text': reply_to_text or replied_message.get('text', '')
                }
    
    # Create new message
    # Note: is_read doesn't matter for sender's own messages since unread_count only counts messages from others
    new_message = {
        'id': new_message_id,
        'sender': current_username,
        'sender_avatar': sender_avatar,
        'sender_name': sender_full_name,
        'sender_full_name': sender_full_name,
        'text': message_text,
        'timestamp': datetime.now().strftime('%H:%M'),
        'is_read': False  # This won't affect unread_count since we only count messages from others
    }
    
    # Add reply_to if present
    if reply_to:
        new_message['reply_to'] = reply_to
        
        # Create notification for the user whose message was replied to
        replied_to_username = reply_to.get('sender', '')
        if replied_to_username and replied_to_username != current_username:
            # Create reply notification
            notifications = load_notifications()
            notification_id = max([n.get('id', 0) for n in notifications], default=0) + 1
            
            # Get sender info for notification
            sender_user = get_user_by_username(current_username)
            sender_avatar = sender_user.get('avatar', 'avatar-1.jpg') if sender_user else 'avatar-1.jpg'
            
            reply_notification = {
                'id': notification_id,
                'type': 'group_reply',
                'user': current_username,
                'target_user': replied_to_username,  # User who should receive this notification
                'avatar': sender_avatar,
                'group_id': group_id,
                'group_name': group.get('name', 'Group'),
                'message_id': new_message_id,
                'replied_to_message_id': reply_to.get('id'),
                'time_ago': 'Just now',
                'is_read': False,
                'action_text': f'replied to your message in {group.get("name", "group")}'
            }
            notifications.insert(0, reply_notification)
            save_notifications(notifications)
    
    # Add message to group
    if 'messages' not in group:
        group['messages'] = []
    group['messages'].append(new_message)
    
    # Update last message preview (optimized - only update last_message, don't process all)
    preview_text = message_text[:50] + '...' if len(message_text) > 50 else message_text
    group['last_message'] = {
        'text': preview_text,
        'timestamp': datetime.now().strftime('%H:%M'),
        'sender': current_username,
        'sender_name': sender_full_name
    }
    
    # NOTE: unread_count is calculated per-user in get_user_groups_optimized() and poll_group_messages()
    # When a user sends a message, their unread_count will be 0 (since they sent the last message)
    # Other users will see unread_count > 0 if they haven't read the new message
    # We don't store a global unread_count on the group since it's user-specific
    
    # Save groups
    if save_groups(groups):
        return jsonify({'success': True, 'message': new_message})
    else:
        return jsonify({'error': 'Failed to save message'}), 500

@app.route('/api/groups/<int:group_id>/poll', methods=['GET'])
@login_required
def poll_group_messages(group_id):
    """SECURE: Poll for new messages in a group - optimized for fast loading."""
    current_username = session.get('username')
    if not current_username or not validate_username(current_username):
        return jsonify({'error': 'Unauthorized'}), 401
    if not isinstance(group_id, int) or group_id < 1:
        return jsonify({'error': 'Invalid group ID'}), 400
    
    last_message_id = request.args.get('last_message_id', type=int)
    if last_message_id is not None and (not isinstance(last_message_id, int) or last_message_id < 0):
        last_message_id = None
    
    # Use optimized function to get group
    group = get_group_by_id_optimized(group_id, current_username)
    
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    
    if not group.get('is_member', False):
        return jsonify({'error': 'Access denied'}), 403
    
    all_messages = group.get('messages', [])
    
    # Filter new messages efficiently
    if last_message_id:
        new_messages = [m for m in all_messages if m.get('id', 0) > last_message_id]
    else:
        new_messages = all_messages
    
    # Only enrich new messages (lazy enrichment with user cache)
    enriched_new_messages = []
    user_cache = {}
    
    for message in new_messages:
        enriched_message = message.copy()
        if 'sender_avatar' not in enriched_message or not enriched_message.get('sender_avatar'):
            sender_username = enriched_message.get('sender')
            if sender_username and validate_username(sender_username):
                # Check cache first
                if sender_username not in user_cache:
                    sender_user = get_user_by_username(sender_username)
                    if sender_user:
                        user_cache[sender_username] = {
                            'avatar': sender_user.get('avatar', 'avatar-1.jpg'),
                            'full_name': sender_user.get('full_name', sender_username)
                        }
                    else:
                        user_cache[sender_username] = {
                            'avatar': 'avatar-1.jpg',
                            'full_name': sender_username
                        }
                
                cached_user = user_cache[sender_username]
                enriched_message['sender_avatar'] = cached_user['avatar']
                enriched_message['sender_full_name'] = cached_user['full_name']
                enriched_message['sender_name'] = cached_user['full_name']
        enriched_new_messages.append(enriched_message)
    
    # Calculate current unread_count (only messages from others that are unread)
    # KEY RULE: If the last message was sent by the current user, their unread_count should be 0
    if all_messages:
        last_msg = all_messages[-1]
        last_message_sender = last_msg.get('sender', '')
        
        # If current user sent the last message, they should see 0 unread notifications
        if last_message_sender == current_username:
            current_unread_count = 0
        else:
            # Count unread messages from others
            current_unread_count = sum(1 for m in all_messages 
                                      if m.get('sender') != current_username and not m.get('is_read', False))
    else:
        current_unread_count = 0
    
    # Return the current unread count (calculated per-user, not stored on group)
    return jsonify({
        'new_messages': enriched_new_messages,
        'last_message_id': max([m.get('id', 0) for m in all_messages], default=0),
        'unread_count': current_unread_count
    })

@app.route('/api/groups/<int:group_id>/mark-read', methods=['POST'])
@login_required
def mark_group_read(group_id):
    """SECURE: Mark all messages in a group as read for the current user - only counts messages from others."""
    current_username = session.get('username')
    if not current_username or not validate_username(current_username):
        return jsonify({'error': 'Unauthorized'}), 401
    if not isinstance(group_id, int) or group_id < 1:
        return jsonify({'error': 'Invalid group ID'}), 400
    
    groups = load_groups()
    group = next((g for g in groups if g.get('id') == group_id), None)
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    
    # Check membership
    is_member = False
    if group.get('admin') == current_username:
        is_member = True
    elif group.get('members'):
        member = next((m for m in group['members'] if m.get('username') == current_username), None)
        if member:
            is_member = True
    
    if not is_member:
        return jsonify({'error': 'Access denied'}), 403
    
    all_messages = group.get('messages', [])
    updated = False
    
    # Mark all messages from others (not from current user) as read
    for message in all_messages:
        if message.get('sender') != current_username and not message.get('is_read', False):
            message['is_read'] = True
            updated = True
    
    # Recalculate unread_count (only messages from others that are unread)
    unread_count = sum(1 for m in all_messages 
                      if m.get('sender') != current_username and not m.get('is_read', False))
    group['unread_count'] = unread_count
    
    if updated:
        if save_groups(groups):
            return jsonify({'success': True, 'unread_count': unread_count})
        else:
            return jsonify({'error': 'Failed to save read status'}), 500
    
    return jsonify({'success': True, 'unread_count': unread_count})

@app.route('/api/groups/search', methods=['GET'])
@login_required
def search_groups():
    """SECURE API endpoint to search groups and messages - optimized for performance."""
    current_username = session.get('username')
    if not current_username or not validate_username(current_username):
        return jsonify({'error': 'Unauthorized'}), 401
    query = request.args.get('q', '').strip().lower()
    if not query:
        return jsonify({'groups': [], 'messages': []})
    
    # Load groups once and get user groups (optimized)
    all_groups = load_groups()
    
    matched_groups = []
    matched_messages = {}
    
    # Search through groups efficiently
    for group in all_groups:
        # Fast membership check
        is_member = False
        if group.get('admin') == current_username:
            is_member = True
        elif group.get('members'):
            for member in group['members']:
                if member.get('username') == current_username:
                    is_member = True
                    break
        
        if not is_member:
            continue
        
        group_name = group.get('name', '').lower()
        group_description = group.get('description', '').lower()
        matches_name = query in group_name or query in group_description
        
        # Search messages only if name doesn't match (optimization)
        matching_messages = []
        if not matches_name:
            group_messages = group.get('messages', [])
            # Only search messages if name didn't match - limit to first 10 matches
            for msg in group_messages:
                msg_text = msg.get('text', '').lower()
                if query in msg_text:
                    matching_messages.append(msg)
                    if len(matching_messages) >= 10:
                        break
        
        if matches_name or matching_messages:
            # Use optimized processing for matched groups
            processed_group = {
                'id': group.get('id'),
                'name': group.get('name', ''),
                'description': group.get('description', ''),
                'avatar': group.get('avatar', 'group-1.jpg'),
                'members_count': group.get('members_count', 0),
                'category': group.get('category', 'other'),
                'privacy': group.get('privacy', 'Public'),
                'is_member': True,
                'unread_count': 0,
                'last_message': {'text': '', 'timestamp': '', 'sender': '', 'sender_name': ''}
            }
            
            # Process last message
            group_messages = group.get('messages', [])
            if group_messages:
                last_msg = group_messages[-1]
                msg_text = last_msg.get('text', '')
                processed_group['last_message'] = {
                    'text': msg_text[:50] + ('...' if len(msg_text) > 50 else ''),
                    'timestamp': last_msg.get('timestamp', ''),
                    'sender': last_msg.get('sender', ''),
                    'sender_name': last_msg.get('sender_name', last_msg.get('sender', ''))
                }
                processed_group['_sort_key'] = last_msg.get('id', 0)
                
                # Calculate unread count
                # KEY RULE: If the last message was sent by the current user, their unread_count should be 0
                last_message_sender = last_msg.get('sender', '')
                if last_message_sender == current_username:
                    processed_group['unread_count'] = 0
                else:
                    # Count unread messages from others
                    unread_count = sum(1 for m in group_messages 
                                     if m.get('sender') != current_username and not m.get('is_read', False))
                    processed_group['unread_count'] = unread_count
            else:
                processed_group['_sort_key'] = 0
            
            matched_groups.append(processed_group)
            if matching_messages:
                matched_messages[group.get('id')] = matching_messages
    
    # Sort by last message ID (most recent first)
    matched_groups.sort(key=lambda g: g.get('_sort_key', 0), reverse=True)
    # Remove internal sort key
    for group in matched_groups:
        group.pop('_sort_key', None)
    
    return jsonify({'groups': matched_groups, 'messages': matched_messages})

@app.route('/api/groups/<int:group_id>/join', methods=['POST'])
@login_required
def toggle_group_membership(group_id):
    """Toggle membership status for a group"""
    groups = load_groups()
    target_group = None
    
    for group in groups:
        if group['id'] == group_id:
            target_group = group
            # Toggle membership status
            is_member = group.get('is_member', False)
            group['is_member'] = not is_member
            
            # Update members count
            if group['is_member']:
                group['members_count'] = group.get('members_count', 0) + 1
            else:
                group['members_count'] = max(0, group.get('members_count', 0) - 1)
            break
    
    if target_group:
        save_groups(groups)
        return jsonify({
            'success': True, 
            'is_member': target_group.get('is_member', False),
            'members_count': target_group.get('members_count', 0)
        })
    else:
        return jsonify({'success': False, 'error': 'Group not found'}), 404

@app.route('/api/groups/<int:group_id>/update', methods=['POST'])
@login_required
def update_group(group_id):
    """Update group settings (admin only)"""
    current_username = session.get('username')
    if not current_username:
        return jsonify({'error': 'Unauthorized'}), 401
    
    groups = load_groups()
    group = next((g for g in groups if g.get('id') == group_id), None)
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    
    # Check if user is admin
    is_admin = False
    if group.get('members'):
        member = next((m for m in group['members'] if m.get('username') == current_username and m.get('is_admin')), None)
        is_admin = member is not None
    elif group.get('admin') == current_username:
        is_admin = True
    
    if not is_admin:
        return jsonify({'error': 'Only admins can update group settings'}), 403
    
    # Handle file upload (avatar)
    if 'avatar' in request.files:
        file = request.files['avatar']
        if file and file.filename:
            filename = secure_filename(file.filename)
            unique_filename = f"{group_id}_{int(time.time())}_{filename}"
            groups_folder = os.path.join('database', 'groups')
            os.makedirs(groups_folder, exist_ok=True)
            file_path = os.path.join(groups_folder, unique_filename)
            file.save(file_path)
            group['avatar'] = unique_filename
    
    # Handle JSON updates
    if request.is_json:
        data = request.get_json()
        if 'name' in data:
            group['name'] = data['name'].strip()[:50]
        if 'description' in data:
            group['description'] = data['description'].strip()[:200]
        if 'privacy' in data:
            if data['privacy'] in ['Public', 'Private']:
                group['privacy'] = data['privacy']
    
    if save_groups(groups):
        return jsonify({'success': True})
    return jsonify({'error': 'Failed to save'}), 500

@app.route('/api/groups/<int:group_id>/add-member', methods=['POST'])
@login_required
def add_group_member(group_id):
    """Add a member to the group (admin only)"""
    current_username = session.get('username')
    if not current_username:
        return jsonify({'error': 'Unauthorized'}), 401
    
    groups = load_groups()
    group = next((g for g in groups if g.get('id') == group_id), None)
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    
    # Check if user is admin
    is_admin = False
    if group.get('members'):
        member = next((m for m in group['members'] if m.get('username') == current_username and m.get('is_admin')), None)
        is_admin = member is not None
    elif group.get('admin') == current_username:
        is_admin = True
    
    if not is_admin:
        return jsonify({'error': 'Only admins can add members'}), 403
    
    data = request.get_json()
    username = data.get('username')
    if not username:
        return jsonify({'error': 'Username required'}), 400
    
    # Get user info
    user = get_user_by_username(username)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Initialize members array if not exists
    if 'members' not in group:
        group['members'] = []
    
    # Check if already a member
    if any(m.get('username') == username for m in group['members']):
        return jsonify({'error': 'User is already a member'}), 400
    
    # Add member
    group['members'].append({
        'username': username,
        'full_name': user.get('full_name', username),
        'avatar': user.get('avatar', 'avatar-1.jpg'),
        'is_admin': False,
        'joined_at': datetime.now().strftime('%Y-%m-%d')
    })
    group['members_count'] = len(group['members'])
    
    if save_groups(groups):
        return jsonify({'success': True})
    return jsonify({'error': 'Failed to save'}), 500

@app.route('/api/groups/<int:group_id>/remove-member', methods=['POST'])
@login_required
def remove_group_member(group_id):
    """Remove a member from the group (admin only)"""
    current_username = session.get('username')
    if not current_username:
        return jsonify({'error': 'Unauthorized'}), 401
    
    groups = load_groups()
    group = next((g for g in groups if g.get('id') == group_id), None)
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    
    # Check if user is admin
    is_admin = False
    if group.get('members'):
        member = next((m for m in group['members'] if m.get('username') == current_username and m.get('is_admin')), None)
        is_admin = member is not None
    elif group.get('admin') == current_username:
        is_admin = True
    
    if not is_admin:
        return jsonify({'error': 'Only admins can remove members'}), 403
    
    data = request.get_json()
    username = data.get('username')
    if not username:
        return jsonify({'error': 'Username required'}), 400
    
    # Cannot remove admin
    if group.get('admin') == username:
        return jsonify({'error': 'Cannot remove group admin'}), 400
    
    # Remove member
    if 'members' in group:
        group['members'] = [m for m in group['members'] if m.get('username') != username]
        group['members_count'] = len(group['members'])
    
    if save_groups(groups):
        return jsonify({'success': True})
    return jsonify({'error': 'Failed to save'}), 500

@app.route('/api/groups/<int:group_id>/leave', methods=['POST'])
@login_required
def leave_group(group_id):
    """Leave a group"""
    current_username = session.get('username')
    if not current_username:
        return jsonify({'error': 'Unauthorized'}), 401
    
    groups = load_groups()
    group = next((g for g in groups if g.get('id') == group_id), None)
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    
    # Cannot leave if admin
    if group.get('admin') == current_username:
        return jsonify({'error': 'Admin cannot leave group. Delete group instead.'}), 400
    
    # Remove from members
    if 'members' in group:
        group['members'] = [m for m in group['members'] if m.get('username') != current_username]
        group['members_count'] = len(group['members'])
    
    if save_groups(groups):
        return jsonify({'success': True})
    return jsonify({'error': 'Failed to save'}), 500

@app.route('/api/groups/<int:group_id>/delete', methods=['POST'])
@login_required
def delete_group(group_id):
    """Delete a group (admin only)"""
    current_username = session.get('username')
    if not current_username:
        return jsonify({'error': 'Unauthorized'}), 401
    
    groups = load_groups()
    group = next((g for g in groups if g.get('id') == group_id), None)
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    
    # Check if user is admin
    is_admin = False
    if group.get('members'):
        member = next((m for m in group['members'] if m.get('username') == current_username and m.get('is_admin')), None)
        is_admin = member is not None
    elif group.get('admin') == current_username:
        is_admin = True
    
    if not is_admin:
        return jsonify({'error': 'Only admins can delete groups'}), 403
    
    # Remove group
    groups = [g for g in groups if g.get('id') != group_id]
    
    if save_groups(groups):
        return jsonify({'success': True})
    return jsonify({'error': 'Failed to save'}), 500

@app.route('/api/settings')
def api_settings():
    """API endpoint to get settings"""
    settings = load_settings()
    return jsonify(settings)

@app.route('/api/temp-upload', methods=['POST'])
def temp_upload():
    """Upload media to temporary storage (20 minute expiry)"""
    try:
        print("Temp upload endpoint called")
        
        # Check if file is present
        if 'media' not in request.files:
            print("No media file in request")
            return jsonify({'success': False, 'error': 'No media file provided'}), 400
        
        file = request.files['media']
        print(f"Received file: {file.filename}")
        
        # Validate file
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'success': False, 'error': f'Invalid file type. Allowed: {ALLOWED_EXTENSIONS}'}), 400
        
        # Generate unique filename
        file_ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"{uuid.uuid4()}.{file_ext}"
        print(f"Generated filename: {filename}")
        
        # Ensure temp directory exists
        temp_folder = app.config.get('TEMP_UPLOAD_FOLDER', 'database/create')
        os.makedirs(temp_folder, exist_ok=True)
        print(f"Temp folder: {temp_folder}")
        
        # Save file
        filepath = os.path.join(temp_folder, filename)
        file.save(filepath)
        print(f"File saved to: {filepath}")
        
        # Track the file with timestamp
        temp_files = load_temp_media()
        
        file_info = {
            'filename': filename,
            'file_path': filepath,
            'upload_time': datetime.now().isoformat(),
            'expiry_time': (datetime.now() + timedelta(minutes=20)).isoformat(),
            'file_type': 'video' if file_ext in ['mp4', 'mov', 'avi', 'webm'] else 'image'
        }
        
        temp_files.append(file_info)
        save_temp_media(temp_files)
        print(f"File info saved. Total temp files: {len(temp_files)}")
        
        return jsonify({
            'success': True,
            'filename': filename,
            'file_path': filepath,
            'file_url': f'/api/temp-media/{filename}',
            'expiry_time': file_info['expiry_time'],
            'file_type': file_info['file_type']
        }), 200
        
    except Exception as e:
        print(f"Error in temp upload: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/temp-media/<filename>')
def serve_temp_media(filename):
    """Serve temporary media files"""
    temp_folder = app.config.get('TEMP_UPLOAD_FOLDER', 'database/create')
    print(f"Serving temp media: {filename} from {temp_folder}")
    
    # Check if file exists
    file_path = os.path.join(temp_folder, filename)
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return jsonify({'error': 'File not found'}), 404
    
    # Serve the file
    response = send_from_directory(temp_folder, filename)
    
    # Add CORS headers to allow cross-origin access
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

@app.route('/api/temp-media-info')
def temp_media_info():
    """Get information about temporary media files"""
    temp_files = load_temp_media()
    current_time = datetime.now()
    
    # Add remaining time to each file
    for file_info in temp_files:
        upload_time = datetime.fromisoformat(file_info['upload_time'])
        expiry_time = datetime.fromisoformat(file_info['expiry_time'])
        remaining_seconds = (expiry_time - current_time).total_seconds()
        file_info['remaining_seconds'] = max(0, int(remaining_seconds))
        file_info['remaining_minutes'] = max(0, int(remaining_seconds / 60))
    
    return jsonify({
        'success': True,
        'temp_files': temp_files,
        'total_files': len(temp_files)
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
