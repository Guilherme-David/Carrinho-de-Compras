from flask_login import UserMixin
from flask import session
from werkzeug.security import generate_password_hash


class User(UserMixin):
    '''
        # Classe Usuário: Importante!
        - UserMixin: Sobrescrever os Métodos:
        1. ```is_authenticated``` : checar se o usuário está autenticado;
        2. ```is_active``` : verifica se o usuário está ativo;
        3. ```is_anonymous``` : verificar se é usuário anônimo;
        4. ```get_id``` : obter o id do usuário.
    '''
    email: str
    senha: str
    def __init__(self, email:str, senha: str):
        '''Inicializa o Usuário, recebe ```email``` (id) e ```senha``` como parâmetros.'''
        self.email = email
        self.senha = senha
        
    @classmethod
    def get(cls, user_id):
        '''Utilizado para pegar o Usuário, com base na lista de usuários criada na sessão.
        - Se tiver id/email na sessão de usuários, o usuário será retornado como User.'''
        lista = session.get('usuarios') # Lista guarda a sessão Usuários
        if user_id in lista.keys():
            user = User(email=user_id, senha=lista[user_id]) 
            user.id = user_id
            return user 

    @classmethod
    def all(cls):
        '''Retorna todos os emails da sessao'''
        return session['usuarios'].keys()

    @classmethod
    def find(cls, email):
        '''Verifica se o email passado como PARÂMETRO está na sessão de usuários.
        - Se estiver: retorna o usuário do tipo User.
        - Se não: retorna False, o usuário não está cadastrado.'''
        if email in session['usuarios'].keys():
            lista = session['usuarios']
            user = User(email=email, senha=lista[email])
            user.id = id=email
            return user
        return False

    def save(self):
        '''Ao efetuar o cadastro, o usuário é salvo na sessão.
        - Salva a senha criptografada.'''
        lista = session.get('usuarios')
        lista[self.email] = generate_password_hash(self.senha)
        session['usuarios'] = lista
        return True # Deu certo salvar.
    
    def get_id(self):
        '''MODIFICADO: Retorna o id do usuário: seu email.'''
        return self.email