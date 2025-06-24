function Login({ onLogin }) {
  const [email, setEmail] = React.useState('');
  const [senha, setSenha] = React.useState('');
  const [erro, setErro] = React.useState('');

  const submit = async (e) => {
    e.preventDefault();
    try {
      await loginApi(email, senha);
      setErro('');
      onLogin();
    } catch (err) {
      setErro(err.message);
    }
  };

  return (
    <form onSubmit={submit} style={{ marginBottom: '1rem' }}>
      <h3>Login</h3>
      <input placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} />
      <input type="password" placeholder="Senha" value={senha} onChange={e => setSenha(e.target.value)} />
      <button type="submit">Entrar</button>
      {erro && <div style={{color:'red'}}>{erro}</div>}
    </form>
  );
}
