import EmailForm from './EmailForm'

export default function Home() {
  return (
    <main className="min-h-screen bg-black text-white flex flex-col">
      <header className="bg-[#ec008c] text-black py-4 text-center font-bold text-xl">
        ANÁLISE DE SEGURANÇA CORPORATIVA
      </header>
      <div className="flex-grow flex flex-col items-center pt-8 px-4">
        <EmailForm />
      </div>
    </main>
  )
}