function Feiras() {
  const [feiras, setFeiras] = React.useState([]);
  const [novoNome, setNovoNome] = React.useState('');
  const [erro, setErro] = React.useState('');

  async function carregar() {
    try {
      const dados = await getFeiras();
      setFeiras(dados);
    } catch (err) {
      setErro(err.message);
    }
  }

  React.useEffect(() => {
    carregar();
  }, []);

  async function criar() {
    try {
      await criarFeira(novoNome);
      setNovoNome('');
      carregar();
    } catch (err) {
      alert(err.message);
    }
  }

  async function remover(id) {
    if (!confirm('Deseja remover?')) return;
    try {
      await deletarFeira(id);
      carregar();
    } catch (err) {
      alert(err.message);
    }
  }

  return (
    <div>
      <h3>Feiras</h3>
      {erro && <div style={{color:'red'}}>{erro}</div>}
      <ul>
        {feiras.map(f => (
          <li key={f.id}>{f.nome} <button onClick={() => remover(f.id)}>Excluir</button></li>
        ))}
      </ul>
      <input placeholder="Nova feira" value={novoNome} onChange={e => setNovoNome(e.target.value)} />
      <button onClick={criar}>Criar</button>
    </div>
  );
}
