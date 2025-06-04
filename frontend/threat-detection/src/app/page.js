import EmailForm from './EmailForm'

export default function Home() {
  return (
    <main className="min-h-screen flex flex-col items-center bg-black text-white">
      <header className="w-full bg-[#ec008c] py-4 text-center">
        <h1 className="font-bold text-lg md:text-2xl uppercase">ANÁLISE DE SEGURANÇA CORPORATIVA</h1>
      </header>
      <div className="flex-1 flex items-center justify-center w-full px-4">
        <EmailForm />
      </div>
    </main>
  )
}