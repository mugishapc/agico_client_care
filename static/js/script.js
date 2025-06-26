// Main JavaScript file
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Image preview for uploads
    document.querySelectorAll('input[type="file"]').forEach(input => {
        input.addEventListener('change', function() {
            if (this.files && this.files[0]) {
                const previewId = this.getAttribute('data-preview');
                if (previewId) {
                    const preview = document.getElementById(previewId);
                    const reader = new FileReader();
                    
                    reader.onload = function(e) {
                        preview.src = e.target.result;
                        preview.style.display = 'block';
                    }
                    
                    reader.readAsDataURL(this.files[0]);
                }
            }
        });
    });
    
    // Chat functionality
    const chatForm = document.getElementById('chat-form');
    if (chatForm) {
        chatForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const messageInput = this.querySelector('input[name="message"]');
            const message = messageInput.value.trim();
            
            if (message) {
                // In a real app, this would send via SocketIO or AJAX
                console.log('Message sent:', message);
                messageInput.value = '';
            }
        });
    }
    
    // Tab functionality for accident declaration
    const accidentTabs = document.querySelectorAll('.accident-tab');
    if (accidentTabs.length) {
        accidentTabs.forEach(tab => {
            tab.addEventListener('click', function(e) {
                e.preventDefault();
                const target = this.getAttribute('data-target');
                
                document.querySelectorAll('.accident-step').forEach(step => {
                    step.classList.remove('active');
                });
                
                document.querySelector(target).classList.add('active');
                
                accidentTabs.forEach(t => t.classList.remove('active'));
                this.classList.add('active');
            });
        });
    }
    
    // Status filter functionality
    const statusFilter = document.getElementById('status-filter');
    if (statusFilter) {
        statusFilter.addEventListener('change', function() {
            this.form.submit();
        });
    }
    
    // Request type tabs
    const requestTypeTabs = document.querySelectorAll('.request-type-tab');
    if (requestTypeTabs.length) {
        requestTypeTabs.forEach(tab => {
            tab.addEventListener('click', function(e) {
                e.preventDefault();
                const type = this.getAttribute('data-type');
                window.location.href = `${window.location.pathname}?type=${type}`;
            });
        });
    }
});