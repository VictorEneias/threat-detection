import EmailForm from './EmailForm'

export default function Home() {
  return (
    <main className="min-h-screen flex items-center justify-center bg-gray-100">
      <div className="bg-white shadow-lg p-6 rounded-lg w-full max-w-xl">
        <h1 className="text-2xl font-bold mb-4 text-gray-800">Análise de Segurança Corporativa</h1>
        <EmailForm />
      </div>
    </main>
  )
}