/**
 * Theme Detection and Management
 * Handles automatic theme switching based on device preferences
 */

class ThemeManager {
    constructor() {
        this.theme = this.getSystemTheme();
        this.init();
    }

    /**
     * Get system theme preference
     */
    getSystemTheme() {
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            return 'dark';
        }
        return 'light';
    }


    /**
     * Apply theme to document
     */
    applyTheme(theme) {
        document.documentElement.setAttribute('data-bs-theme', theme);
        this.theme = theme;
    }

    /**
     * Initialize theme system
     */
    init() {
        // Always use system theme - no manual override
        this.theme = this.getSystemTheme();
        this.applyTheme(this.theme);

        // Listen for system theme changes
        if (window.matchMedia) {
            const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
            
            // Handle system theme changes
            const handleThemeChange = (e) => {
                this.applyTheme(e.matches ? 'dark' : 'light');
            };

            // Add listener for system theme changes
            mediaQuery.addEventListener('change', handleThemeChange);
        }
    }


    /**
     * Get current theme
     */
    getCurrentTheme() {
        return this.theme;
    }
}

// Initialize theme manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.themeManager = new ThemeManager();
    
    // Initialize image orientation detection
    initializeImageOrientationDetection();
});

/**
 * Image Orientation Detection
 * Detects image aspect ratio and applies appropriate CSS class
 */
function initializeImageOrientationDetection() {
    // Function to detect and apply orientation class
    function detectImageOrientation(img) {
        const container = img.closest('.post-image-container');
        if (!container) return;
        
        // Calculate aspect ratio
        const aspectRatio = img.naturalWidth / img.naturalHeight;
        
        // Remove existing orientation classes
        container.classList.remove('portrait', 'landscape', 'square');
        
        // Apply appropriate orientation class based on aspect ratio
        if (aspectRatio > 1.3) {
            container.classList.add('landscape');
        } else if (aspectRatio < 0.9) {
            container.classList.add('portrait');
        } else {
            container.classList.add('square');
        }
    }
    
    // Detect orientation for all existing images
    const images = document.querySelectorAll('.post-image');
    images.forEach(img => {
        if (img.complete) {
            // Image already loaded
            detectImageOrientation(img);
        } else {
            // Wait for image to load
            img.addEventListener('load', () => detectImageOrientation(img));
        }
    });
    
    // Use MutationObserver to detect dynamically added images
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            mutation.addedNodes.forEach((node) => {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    // Check if the added node is an image or contains images
                    const images = node.querySelectorAll ? node.querySelectorAll('.post-image') : [];
                    if (node.classList && node.classList.contains('post-image')) {
                        images.push(node);
                    }
                    
                    images.forEach(img => {
                        if (img.complete) {
                            detectImageOrientation(img);
                        } else {
                            img.addEventListener('load', () => detectImageOrientation(img));
                        }
                    });
                }
            });
        });
    });
    
    // Start observing the document body for changes
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ThemeManager;
}
