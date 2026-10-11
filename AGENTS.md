# Instruções Voltolini — Mobile Decision Core

- Entregas ao proprietário em português brasileiro. Novas pastas usam Voltolini ou mobile-decision e finalidade; não usam fornecedor/modelo como identidade.
- Preservar ownership e trabalho concorrente. Trabalhar em missões pequenas com responsável, área exclusiva, provas e revisão. Não modificar outros projetos, credenciais ou configurações globais.
- Pesos, caches, segredos, dados, rótulos, predições, runtime, bancos, logs, backups e checkpoints ficam fora do Git. Nunca copiar evidências privadas por recursão ou importar histórico privado.
- Antes de commit/push, revisar a lista exata de arquivos, fontes/licenças, segredos e paths privados. Publicar somente após autorização aplicável; não executar deploy/merge implícito. Configurar identidade Git somente local ao projeto.
- Usar os testes stdlib públicos isolados. Não importar o core neural nem executar treino/inferência/calibração/SDK remoto para testar consultas. Integrações privadas ausentes devem ser identificadas como não verificadas, nunca contadas como PASS sintético.
- G0–G8 permanecem sem aprovação integral. Separar estrutura/hash, autenticidade, execução e qualidade. Não aceitar status/correct autodeclarado como autoridade nem remover erros/timeouts do denominador.
- Acompanhamento deve mostrar estado real, fonte/horário/expiração, resultados e próximo passo. Dado ausente é null/indisponível; fixture, snapshot, replay e execução ao vivo são distintos. GET não infere, treina, escreve nem inicia experimentos. Alterações visuais seguem revisão prévia.
- Diagnosticar rede/rota antes de atribuir falha a serviço remoto; separar DNS/TCP/SSH/HTTP e sandbox. Não alterar rede, serviços, permissões ou comprar recursos sem mandato.
- Preferir stdlib e menor consumo comprovado; não instalar dependências ou usar APIs pagas como fallback automático. Registrar falhas, decisões e limites com proveniência sanitizada.
