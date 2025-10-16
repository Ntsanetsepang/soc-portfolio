// Main JavaScript for Security Operations Portfolio Site

document.addEventListener('DOMContentLoaded', function() {
    // Smooth scrolling for navigation links
    const navLinks = document.querySelectorAll('nav a, .hero-buttons a');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            // Only apply to links that point to an ID on the page
            if (this.getAttribute('href').startsWith('#')) {
                e.preventDefault();
                
                const targetId = this.getAttribute('href');
                const targetElement = document.querySelector(targetId);
                
                if (targetElement) {
                    // Get the height of the fixed header
                    const headerHeight = document.querySelector('header').offsetHeight;
                    
                    // Calculate the position to scroll to (accounting for the header)
                    const targetPosition = targetElement.offsetTop - headerHeight;
                    
                    // Smooth scroll to the target
                    window.scrollTo({
                        top: targetPosition,
                        behavior: 'smooth'
                    });
                }
            }
        });
    });
    
    // Form submission handling
    const contactForm = document.getElementById('contactForm');
    
    if (contactForm) {
        contactForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Get form values
            const name = document.getElementById('name').value;
            const email = document.getElementById('email').value;
            const message = document.getElementById('message').value;
            
            // Simple validation
            if (!name || !email || !message) {
                alert('Please fill in all fields');
                return;
            }
            
            // In a real implementation, you would send this data to a server
            // For this demo, we'll just show a success message
            alert(`Thank you for your message, ${name}! This is a demo form, so no message was actually sent.`);
            
            // Reset the form
            contactForm.reset();
        });
    }
    
    // Add active class to nav links based on scroll position
    function updateActiveNavLink() {
        const sections = document.querySelectorAll('section');
        const navLinks = document.querySelectorAll('nav a');
        
        // Get current scroll position
        const scrollPosition = window.scrollY;
        
        // Loop through sections to find the one in view
        sections.forEach(section => {
            const sectionTop = section.offsetTop - 100; // Adjust for header
            const sectionHeight = section.offsetHeight;
            const sectionId = section.getAttribute('id');
            
            if (scrollPosition >= sectionTop && scrollPosition < sectionTop + sectionHeight) {
                // Remove active class from all links
                navLinks.forEach(link => {
                    link.classList.remove('active');
                });
                
                // Add active class to corresponding nav link
                const activeLink = document.querySelector(`nav a[href="#${sectionId}"]`);
                if (activeLink) {
                    activeLink.classList.add('active');
                }
            }
        });
    }
    
    // Add scroll event listener
    window.addEventListener('scroll', updateActiveNavLink);
    
    // Initialize active nav link on page load
    updateActiveNavLink();
    
    // Add animation on scroll
    function revealOnScroll() {
        const elements = document.querySelectorAll('.skill-category, .portfolio-item, .timeline-item');
        const windowHeight = window.innerHeight;
        
        elements.forEach(element => {
            const elementTop = element.getBoundingClientRect().top;
            const elementVisible = 150;
            
            if (elementTop < windowHeight - elementVisible) {
                element.classList.add('visible');
            }
        });
    }
    
    // Add CSS for the animation
    const style = document.createElement('style');
    style.textContent = `
        .skill-category, .portfolio-item, .timeline-item {
            opacity: 0;
            transform: translateY(30px);
            transition: opacity 0.6s ease, transform 0.6s ease;
        }
        
        .skill-category.visible, .portfolio-item.visible, .timeline-item.visible {
            opacity: 1;
            transform: translateY(0);
        }
        
        .timeline-item:nth-child(even) {
            transform: translateY(30px) translateX(30px);
        }
        
        .timeline-item:nth-child(even).visible {
            transform: translateY(0) translateX(0);
        }
        
        .timeline-item:nth-child(odd) {
            transform: translateY(30px) translateX(-30px);
        }
        
        .timeline-item:nth-child(odd).visible {
            transform: translateY(0) translateX(0);
        }
        
        @media (max-width: 768px) {
            .timeline-item:nth-child(odd), .timeline-item:nth-child(even) {
                transform: translateY(30px);
            }
            
            .timeline-item:nth-child(odd).visible, .timeline-item:nth-child(even).visible {
                transform: translateY(0);
            }
        }
    `;
    document.head.appendChild(style);
    
    // Add scroll event listener for animations
    window.addEventListener('scroll', revealOnScroll);
    
    // Initialize animations on page load
    revealOnScroll();
    
    // Add active class to navigation on scroll
    const nav = document.querySelector('header');
    
    window.addEventListener('scroll', function() {
        if (window.scrollY > 100) {
            nav.classList.add('scrolled');
        } else {
            nav.classList.remove('scrolled');
        }
    });
    
    // Add CSS for the scrolled header
    const headerStyle = document.createElement('style');
    headerStyle.textContent = `
        header {
            transition: background-color 0.3s ease, padding 0.3s ease;
        }
        
        header.scrolled {
            background-color: rgba(44, 62, 80, 0.95);
            padding: 10px 0;
        }
    `;
    document.head.appendChild(headerStyle);
});