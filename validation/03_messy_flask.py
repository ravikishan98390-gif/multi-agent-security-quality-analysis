from flask import Flask, request, render_template_string, session

app = Flask(__name__)

# Missing @login_required (Vulnerability: broken_access_control, line 6)
@app.route('/admin/dashboard')
def admin_dashboard():
    # Vulnerability: XSS via unescaped variable in render_template_string (line 10)
    user_input = request.args.get('search_query', '')
    template = f"<h1>Admin Dashboard</h1><p>Results for: {user_input}</p>"
    
    html = render_template_string(template)
    
    # Code Smell: Deep Nesting and Cyclomatic Complexity
    if 'user_role' in session:
        if session['user_role'] == 'admin':
            for i in range(10):
                if i % 2 == 0:
                    if i > 5:
                        for j in range(3):
                            if j == 1:
                                print("Complex nested logic here")
                    else:
                        print("Another branch")
                else:
                    if i < 3:
                        print("Small odd number")
                    else:
                        print("Large odd number")
        elif session['user_role'] == 'manager':
            if True:
                if True:
                    if True:
                        print("Deeply nested manager logic")
        else:
            print("Access Denied for role:", session['user_role'])
    else:
        print("No session role")
        
    return html

if __name__ == '__main__':
    app.run(debug=True)
