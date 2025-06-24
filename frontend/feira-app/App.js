function App() {
  const [logado, setLogado] = React.useState(!!localStorage.getItem('token'));

  return (
    <div>
      {logado ? (
        <div>
          <button onClick={() => { setToken(null); setLogado(false); }}>Sair</button>
          <Feiras />
        </div>
      ) : (
        <Login onLogin={() => setLogado(true)} />
      )}
    </div>
  );
}

ReactDOM.render(<App />, document.getElementById('root'));
