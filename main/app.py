# 0 - Importar os módulos
from flask import Flask, session, render_template, request, flash, redirect, url_for
from werkzeug.security import check_password_hash
from modelos import User

# 1 - Adicionar o LoginManager
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
login_manager = LoginManager()
# 1.1 - Adicionar o app
app = Flask(__name__)

# 2 - Configurar app para trabalhar junto com flask-login
login_manager.init_app(app)

# 3 - Necessário adicionar uma chave secreta para aplicação
app.secret_key = 'SECRETODMSPOW'

# 4 - Função utilizada para carregar o usuário da sessão (logado)
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# 5 - Página Inicial
@app.route('/')
def index():
    if 'usuarios' not in session: # Se a sessão não possui usuários
        session['usuarios'] = {} # Cria a sessão.
    return render_template('index.html', users=User.all())

# 6 - Cadastrar Usuário
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['password']

        usuarios = User.all() # Pega os emails de session['usuarios']

        if email not in usuarios: # Se o usuário não está cadastrado
            user = User(email=email, senha=senha) # Cria o Usuário
            user.save() # Salva o usuario na sessão
            login_user(user) # Loga o Usuário
            flash('Cadastro Realizado com Sucesso') # Mensagem de Sucesso
            return redirect(url_for('login'))
        
    return render_template('pages/auth/register.html')

# 7 - Logar o Usuario
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['password']
        
        user = User.find(email) # Procura o usuario com base no email
        if user == False: # Se o retorno acima for False, o email não está cadastrado
            flash('Email Inexistente, Faça seu Cadastro') # Email inexistente
            return redirect(url_for('register'))

        # Se o email existir
        if check_password_hash(user.senha, senha): # Se a senha estiver correta
            login_user(user)
            flash('Você está logado')
            return redirect(url_for('dash'))
        else:
            flash('Dados incorretos') # Senha incorreta
            return redirect(url_for('login'))
        
    return render_template('pages/auth/login.html')

# 8 - Rotas Bloqueadas por Login
# 8.1 - Produtos
@app.route('/dashboard')
@login_required # precisa de login
def dash():
    produtos = get_produtos()
    return render_template('pages/produtos.html', produtos=produtos)

def get_produtos():
    produtos =[{'nome': 'Tenis 1', 'preco': 200, 'id': 0},
            {'nome': 'Camiseta', 'preco': 190, 'id': 1},
            {'nome': 'Corrente', 'preco': 400, 'id': 2}]
    return produtos

# 8.2 - logout
@app.route('/logout')
@login_required
def logout():
    logout_user() # desloga o usuario logado
    session['usuarios'] = {}
    return redirect(url_for('index'))

# 10 - Carrinho de Compras
@app.route('/add_to_cart/<int:id>')
@login_required
def add_to_cart(id):
    if 'carrinho' not in session:
        session['carrinho'] = []

    carrinho = session['carrinho']
    
    produtos = get_produtos()
    for produto in produtos:
        if id == produto['id']:
            carrinho.append(produto['id'])

    session['carrinho'] = carrinho
    return redirect(url_for('dash'))

@app.route('/remove_from_cart/<int:id>')
@login_required
def remove_from_cart(id):
    for item in session['carrinho']:
        if item == id:
            session['carrinho'].remove(id)
    return redirect(url_for('carrinho'))

@app.route('/carrinho')
@login_required
def carrinho():
    if 'carrinho' in session:
            carrinho_ids = session.get('carrinho', [])
    produtos_disponiveis = get_produtos()

    carrinho_real = []
    for produto_id in carrinho_ids:
        for produto in produtos_disponiveis:
            if produto['id'] == produto_id:
                carrinho_real.append(produto)
                break

        
    return render_template('pages/cart.html', carrinho=carrinho_real, produtos=get_produtos())