'use strict';
let timer = null;
let pending = false;
let last = null;
const byId = id => document.getElementById(id);
const text = (id, value) => { byId(id).textContent = value; };
const date = value => value ? new Date(value).toLocaleString('pt-BR', {timeZoneName: 'short'}) : 'indisponível';
function element(tag, value, className) {
  const node = document.createElement(tag); node.textContent = value;
  if (className) node.className = className;
  return node;
}
function render(payload) {
  const source = id => payload.sources.find(item => item.id === id);
  const label = item => item ? `${item.status} • registro ${date(item.recorded_at)}` : 'UNAVAILABLE';
  const gateSource = source('gates');
  byId('gates').replaceChildren();
  for (let i = 0; i < 9; i++) {
    const gate = `G${i}`, row = gateSource?.data?.gates?.[gate];
    const section = element('div', '', 'timeline-step');
    section.append(element('h3', gate), element('div', row?.status || 'NOT_VERIFIED', 'status-indicator status-pending'));
    section.title = row?.reason || 'Sem fonte calculada disponível'; byId('gates').append(section);
  }
  text('gate-note', `${label(gateSource)} • freshness da origem: ${gateSource?.data?.freshness || 'indisponível'} • expires_at da origem: ${gateSource?.data?.expires_at ?? 'null'}. Fonte: gates.`);
  const acceptance = source('acceptance'), tests = source('tests');
  text('acceptance', acceptance?.data ? `R1B.1A-R2: ${acceptance.data.accepted ? 'microetapa aceita' : 'sem aceite'}; ${label(acceptance)}. Não aprova gates. Fonte: acceptance.` : `Aceite indisponível • ${label(acceptance)}.`);
  text('tests', tests?.data ? `${tests.data.tests} testes; exit ${tests.data.exit}; ${tests.data.skipped} skips • ${label(tests)}. Fonte: tests; somente checks estruturais.` : `Testes indisponíveis • ${label(tests)}.`);
  const capacity = source('capacity');
  const policy = source('policy');
  text('capacity', `Política registrada: ${policy?.data?.scope || 'indisponível'}. Capacidade atual não medida por esta consulta. ${label(capacity)}.${capacity?.data ? ` Última medição: RAM livre ${capacity.data.memory_available_kib} KiB; swap livre ${capacity.data.swap_free_kib} KiB. Fonte capacity; respeitar data/expiração.` : ''} Política: fonte policy • ${label(policy)}.`);
  const ownership = source('ownership'), guard = source('guard');
  text('ownership', `${label(ownership)} • Última etapa registrada: ${ownership?.data?.phase || 'indisponível'}; responsável ${ownership?.data?.owner || 'indisponível'}. Fonte: ownership. Não é progresso medido.`);
  text('guard', `${label(guard)} • Último turno registrado: ${guard?.data?.last_turn ?? 'indisponível'}; ajuste antigo na fila: ${guard?.data ? String(guard.data.queued_adjustment) : 'indisponível'}. Fonte: guard; não comprova estado atual do Harness.`);
  const progressB1 = source('b1_progress'), reconciliationB1 = source('b1_reconciliation');
  let b1 = byId('b1-summary');
  if (!b1) { b1 = element('p', '', 'meta'); b1.id = 'b1-summary'; byId('ownership').before(b1); }
  const p = progressB1?.data, r = reconciliationB1?.data;
  const outputs = r ? `${r.variant}: ${r.ordered_pairs} outputs completos reconciliados (test ${r.observed_cases.test} + diagnostic ${r.observed_cases.diagnostic}) • snapshot diagnóstico conhecido, sem cegamento` : 'Baseline de outputs reconciliados indisponível';
  const nextStep = p?.next_step === 'Review watchdog exit race and Linux controls before static_catalog_cache dispatch' ?
    'Revisar a corrida de saída do watchdog e os controles Linux antes de despachar static_catalog_cache' : (p?.next_step === 'Fix pure converter Decimal context issue before metrics; real MLflow client passed compatibility, model runs/replay pending' ? 'Corrigir o contexto Decimal do conversor antes das métricas; cliente MLflow compatível, execuções de modelo e replay pendentes' : (p?.next_step || 'indisponível'));
  const monitor = p?.watchdog_abort_field_present ? (p.watchdog_abort_reason ?? 'sem abort reportado') : 'indisponível';
  const returned = p?.execution_finished == null ? 'indisponível' : (p.execution_finished ? 'término reportado' : 'término não reportado');
  b1.textContent = `B1 • Baseline ${outputs}. Reconciliação baseline: ${r?.output_reconciliation || 'indisponível'} • ${label(reconciliationB1)} • SHA256 ${reconciliationB1?.sha256 ?? 'null'}. Recursos da baseline: ${r?.watchdog_abort_reason || 'indisponível'}; aceite ${r?.resource_run_acceptance || 'indisponível'}. Acompanhamento: ${p?.variant || 'variante indisponível'} • fase ${p?.stage || 'indisponível'} • outputs reportados ${p?.completed_cases ?? 'indisponível'}/${p?.expected_cases ?? 'indisponível'}. Dispatch: horário dedicado indisponível; não verificado separadamente. Retorno no acompanhamento: ${returned}; não é execução ao vivo. Recursos do acompanhamento: ${monitor}; aceite ${p?.resource_run_acceptance || 'indisponível'}. Status adicional da segunda variante: ${p?.second_variant || 'indisponível'}. Paridade: ${p?.method_parity || 'indisponível'}; somente diagnóstico, sem benchmark. Conformidade da ordem do protocolo: ${p?.protocol_order_conformity || 'indisponível'}. ${label(progressB1)} • SHA256 ${progressB1?.sha256 ?? 'null'}. Qualidade, latência e custo null; nenhum gate aprovado. Próximo passo registrado: ${nextStep}.`;
  const learning = source('learning_snapshot'), l = learning?.data;
  byId('learning-results').replaceChildren();
  const unavailable = value => value == null ? 'indisponível' : String(value);
  if (l) {
    const initial = l.selection_initial, final = l.selection_final;
    const fraction = (num, den) => `${num}/${den}`;
    const precision = d => d.accepted_accuracy == null ? 'null • nenhuma aceita (NO_ACCEPTED_CASES)' : fraction(d.N_correct_accepted, d.N_accepted);
    const rows = [
      ['Acurácia (corretas / todos)', fraction(initial.N_correct_all, initial.N_all), fraction(final.N_correct_all, final.N_all)],
      ['Respostas aceitas', initial.N_accepted, final.N_accepted],
      ['Corretas entre aceitas', initial.N_correct_accepted, final.N_correct_accepted],
      ['Erradas entre aceitas', initial.N_wrong_accepted, final.N_wrong_accepted],
      ['Precisão das aceitas', precision(initial), precision(final)],
      ['Cobertura (aceitas / elegíveis)', fraction(initial.N_accepted, initial.N_eligible), fraction(final.N_accepted, final.N_eligible)],
      ['Erros / timeouts (preservados no denominador)', `${initial.N_errors} / ${initial.N_timeouts}`, `${final.N_errors} / ${final.N_timeouts}`]
    ];
    for (const values of rows) { const row = element('tr', ''); for (const value of values) row.append(element('td', String(value))); byId('learning-results').append(row); }
    text('learning-note', `${label(learning)} • fonte learning_snapshot • SHA256 ${learning.sha256}. Seleção de desenvolvimento conhecida, usada na escolha do checkpoint; não é teste cego ou qualidade global. Estado ${l.status}; G0–G8 NOT_VERIFIED, release não aprovado.`);
    text('learning-lineage', `${l.completed_epochs} épocas concluídas; ${l.training_optimizer_steps} updates executados no treino. Checkpoint selecionado: época ${l.selected_epoch}, ${l.checkpoint_optimizer_steps} updates incorporados. ${l.changed_parameters}/${l.parameters} parâmetros alterados; ${l.tensors} tensores. SHA256 inicial ${l.initial_checkpoint_sha256}; final selecionado ${l.final_checkpoint_sha256}. Recibos: execução ${l.execution_receipt_sha256}; validação ${l.validation_receipt_sha256}.`);
    text('learning-resources', `Processo completo de treino: duração ${unavailable(l.resources.elapsed_seconds)} s; pico RSS amostrado ${unavailable(l.resources.observed_peak_rss_bytes)} bytes; ${unavailable(l.resources.rss_samples)} amostras; lacunas ${unavailable(l.resources.monitor_gap_count)}. Esses valores não são latência de inferência nem memória isolada do modelo. Latência de inferência: null; custo: null; qualidade global: null.`);
    text('learning-next', `Próximo passo registrado na fonte congelada: ${l.next_step || 'indisponível'}. GET não inicia treino, calibração, tracking ou replay.`);
  } else {
    const row = element('tr', ''); const cell = element('td', 'Snapshot C indisponível; nenhum resultado substituto.'); cell.colSpan = 3; row.append(cell); byId('learning-results').append(row);
    text('learning-note', `${label(learning)} • Sem snapshot C válido. Nenhum aprendizado ou resultado é presumido.`);
    text('learning-lineage', 'Linhagem e parâmetros: indisponíveis.');
    text('learning-resources', 'Recursos do processo: indisponíveis. Latência de inferência, custo e qualidade global: null.');
    text('learning-next', 'Próximo passo: recuperar uma fonte válida; GET não inicia experimentos.');
  }
  const calibration = source('calibration_snapshot'), c = calibration?.data;
  byId('calibration-results').replaceChildren();
  if (c) {
    const ref = c.reference_T1_tau095, rc = ref.counts;
    const percentage = value => value == null ? 'null' : `${(value * 100).toLocaleString('pt-BR', {maximumFractionDigits: 6})}%`;
    const notChosen = `null • ${c.chosen_metrics_reason}`;
    const rows = [
      ['Acurácia (corretas / todos)', `${c.N_correct_all}/${c.N_all} = ${percentage(c.accuracy_all)}`, `${rc.N_correct_all}/${rc.N_all}`],
      ['Temperatura', `${c.chosen_temperature.value} (${c.chosen_temperature.exact}; índice ${c.chosen_temperature.index})`, 'T1 • referência fixa'],
      ['Limiares viáveis', `${c.feasible_thresholds}/${c.threshold_grid_count}`, 'Não seleciona política'],
      ['Limiar escolhido', notChosen, '0,95 • somente descritivo'],
      ['Precisão das aceitas', notChosen, `${rc.N_correct_accepted}/${rc.N_accepted} = ${percentage(ref.precision)}`],
      ['Cobertura (aceitas / elegíveis)', notChosen, `${rc.N_accepted}/${rc.N_eligible} = ${percentage(ref.coverage)}`],
      ['ECE15 • diagnóstico ajustado, não G6', String(c.ece15.value), 'Indisponível neste snapshot']
    ];
    for (const values of rows) { const row = element('tr', ''); for (const value of values) row.append(element('td', String(value))); byId('calibration-results').append(row); }
    text('calibration-note', `${label(calibration)} • fonte calibration_snapshot • SHA256 ${calibration.sha256}. Estado ${c.status}: nenhum limiar viável no método congelado. Calibração de desenvolvimento conhecida, não teste cego nem qualidade global. ${c.temperature_grid_count} temperaturas e ${c.threshold_grid_count} limiares preservados; G0–G8 NOT_VERIFIED, release não aprovado.`);
    text('calibration-reference', `Identidades separadas: temperatura escolhida por NLL sem limiar viável; referência T1/0,95 é apenas descritiva (${ref.scope}). Metas congeladas: precisão ${percentage(c.targets.accepted_precision)}, cobertura ${percentage(c.targets.coverage_eligible)}, ECE ≤ ${c.targets.ece}. A referência não substitui chosen_precision/coverage/threshold null. ECE ajustada é otimista e não aprova G6.`);
    text('calibration-lineage', `Checkpoint final SHA256 ${c.checkpoint_sha256}; resultado ${c.result_sha256}; recibo do fit ${c.fit_receipt_sha256}; revisão independente ${c.independent_review_sha256}. Qualidade global, latência de inferência e custo: null.`);
    text('calibration-next', `Tracking no instante deste snapshot: ${c.tracking}. Próximo passo histórico: ${c.next_step || 'indisponível'}. A etapa posterior deve ser lida nas fontes de coordenação com sua própria data; esta consulta não registra MLflow, não refaz fit, não inicia inferência e não renova o snapshot.`);
  } else {
    const row = element('tr', ''); const cell = element('td', 'Calibração indisponível; nenhuma política ou métrica substituta.'); cell.colSpan = 3; row.append(cell); byId('calibration-results').append(row);
    text('calibration-note', `${label(calibration)} • Sem snapshot de calibração válido. Qualidade global e parâmetros não são presumidos.`);
    text('calibration-reference', 'Referência T1/0,95 indisponível; não preenche métricas escolhidas. Nenhum gate aprovado.');
    text('calibration-lineage', 'Linhagem: indisponível. Qualidade global, latência de inferência e custo: null.');
    text('calibration-next', 'Próximo passo: recuperar fonte válida; GET não inicia fit, tracking ou inferência.');
  }
  const smoke = source('smoke'); byId('smoke-results').replaceChildren();
  const row = document.createElement('tr');
  if (smoke?.data) {
    const d = smoke.data;
    for (const value of [d.case_id, d.candidate_id, d.expected_id, String(d.reported_top_probability),
      `${smoke.status} • ${d.candidate_correct ? 'candidato correto' : 'candidato errado'} • ${d.abstained ? 'absteve' : 'aceitou'}`]) row.append(element('td', value));
    text('smoke-note', `Um caso histórico conhecido • CPU • snapshot_finished • ${label(smoke)} • fonte smoke, SHA256 ${smoke.sha256}. Duração total ${d.duration_including_imports_seconds.toFixed(3)} s inclui imports/carregamento; não é latência de inferência ou P95. Zero aceitas neste smoke: precisão das aceitas null. Qualidade global, latência e custo null; learning ${d.learning}. Intérprete absoluto: ${d.runtime_executable_identity}. GET não reexecuta.`);
  } else {
    const cell = element('td', 'Snapshot do smoke indisponível; nenhum resultado substituto.'); cell.colSpan = 5; row.append(cell);
    text('smoke-note', `${label(smoke)} • Nenhuma inferência é disparada pela consulta. Qualidade, latência, custo e aprendizado não verificados.`);
  }
  byId('smoke-results').append(row);
  byId('sources').replaceChildren();
  for (const s of payload.sources) {
    const row = element('article', '', 'source-row');
    row.append(element('h3', s.id), element('p', `${s.status}${s.error ? ' • '+s.error : ''}`, 'status-indicator status-pending'));
    row.append(element('p', `Registro original: ${date(s.recorded_at)} • Expira: ${date(s.expires_at)} • Modo: ${s.mode}`, 'meta'));
    row.append(element('p', `Coletado: ${date(s.collected_at)} • mtime (não renova validade): ${date(s.source_modified_at)}`, 'meta'));
    row.append(element('p', `SHA256: ${s.sha256 ?? 'null'}`, 'hash'));
    const details = document.createElement('details'); details.append(element('summary', 'Caminho e campos selecionados'));
    details.append(element('p', s.path, 'hash'), element('pre', JSON.stringify(s.data, null, 2)));
    row.append(details); byId('sources').append(row);
  }
}
function log(message) {
  if (!last) byId('logs').replaceChildren();
  byId('logs').prepend(element('p', message));
  while (byId('logs').children.length > 8) byId('logs').lastChild.remove();
}
async function refresh() {
  if (pending) return;
  pending = true; byId('refresh').disabled = true;
  const controller = new AbortController(); const deadline = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch('/api/preview', {cache: 'no-store', signal: controller.signal});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    if (data.schema !== 'voltolini.mobile-decision.preview/1' || !Array.isArray(data.sources)) throw new Error('Contrato inválido');
    const changed = last ? data.sources.filter(s => s.sha256 !== last.sources.find(p => p.id === s.id)?.sha256).map(s => s.id) : [];
    render(data); text('transport', `HTTP disponível • coleta ${date(data.collected_at)}. Consulta ${timer ? 'a cada 15 s' : 'manual'}. Não certifica execução.`);
    log(`${date(data.collected_at)} • HTTP 200 • ${last ? (changed.length ? 'Fontes com hash alterado: '+changed.join(', ') : 'Hashes inalterados; nenhum avanço inferido.') : 'Primeira leitura; sem comparação de progresso.'}`);
    last = data;
  } catch (error) {
    text('transport', `Transporte indisponível: ${error.message}. Registros anteriores STALE; nenhuma atualidade presumida.`);
    if (last) render({...last, sources: last.sources.map(s => ({...s, status: 'STALE', error: 'HTTP_UNAVAILABLE'}))});
    log(`${new Date().toLocaleString('pt-BR')} • Falha de consulta; fontes anteriores não renovadas.`);
  } finally { clearTimeout(deadline); pending = false; byId('refresh').disabled = false; }
}
byId('refresh').addEventListener('click', refresh);
byId('toggle').addEventListener('click', () => {
  if (timer) { clearInterval(timer); timer = null; } else { timer = setInterval(refresh, 15000); }
  byId('toggle').setAttribute('aria-pressed', String(Boolean(timer)));
  text('toggle', timer ? 'Pausar consulta periódica' : 'Ativar consulta a cada 15 s');
  refresh();
});
refresh();
