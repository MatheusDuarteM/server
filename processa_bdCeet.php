<?php

// --- Configurações de Erro e Cabeçalhos ---
// ini_set('display_errors', 1); // DESABILITAR em produção por segurança E PARA API JSON
ini_set('display_errors', 0); // <-- MUDAR PARA 0
error_reporting(E_ALL);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/php_errors.log');

// --- Validação Crítica: Garantir que nada foi enviado antes dos headers ---
if (headers_sent($filename, $linenum)) {
    error_log("Headers já enviados em $filename na linha $linenum antes de definir os headers da API.");
    // Não podemos enviar JSON agora, logamos e saímos com erro genérico
    http_response_code(500);
    // Evita enviar JSON quebrado, mas loga o erro
    echo '{"status":"error_server", "message":"Erro interno: Conflito de saída no servidor."}';
    exit;
}

// --- Cabeçalhos CORS e Content-Type ---
header('Access-Control-Allow-Origin: *'); // Produção: Restrinja a '*' para domínios específicos
header('Access-Control-Allow-Methods: POST, GET, OPTIONS'); // Métodos permitidos
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With'); // Cabeçalhos permitidos
header('Content-Type: application/json; charset=UTF-8'); // Resposta sempre JSON

// --- FUNÇÕES AUXILIARES (Versões Robustas) ---

/**
 * Função centralizada para retornar JSON e encerrar o script.
 */
function respondeJson($status, $mensagem, $dados = [])
{
    $http_code = 500; // Default error_server
    if ($status === 'success') $http_code = 200;
    else if ($status === 'created') $http_code = 201;
    else if ($status === 'info') $http_code = 200;
    else if ($status === 'error_client') $http_code = 400;
    else if ($status === 'unauthorized') $http_code = 401; // Para falha de login
    else if ($status === 'not_found') $http_code = 404;
    else if ($status === 'method_not_allowed') $http_code = 405;

    if (!headers_sent()) {
       http_response_code($http_code);
    } else {
        error_log("Tentativa de definir http_response_code($http_code) após headers serem enviados.");
    }

    $response = ['status' => $status];
    if ($mensagem) $response['message'] = $mensagem;

    // Estrutura flexível para dados
    if (!empty($dados)) {
       if (isset($dados['data']) || isset($dados['total']) || isset($dados['page'])) {
           $response = array_merge($response, $dados);
       } else {
            $response['data'] = $dados; // Aninha em 'data' por padrão
       }
    }

    echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

/**
 * Função de conexão com o banco de dados MySQL (PDO).
 */
function abreConexaoBD()
{
    $nomeServidor = "localhost";
    $nomeusuarios = "root";
    $senhaAcesso = ""; // Considere usar variáveis de ambiente para credenciais
    $nomeBanco = "cadastro"; // Nome do seu banco
    $charset = "utf8mb4";

    try {
        $dsn = "mysql:host=$nomeServidor;dbname=$nomeBanco;charset=$charset";
        $opcoes = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ];
        $conn = new PDO($dsn, $nomeusuarios, $senhaAcesso, $opcoes);
        return $conn;
    } catch (PDOException $e) {
        error_log('Falha ao conectar ao BD: ' . $e->getMessage());
        // Chama respondeJson para erro de servidor padronizado
        respondeJson('error_server', 'Falha na conexão com o banco de dados.');
    }
}


// --- FUNÇÕES DE NEGÓCIO ---

// == USUÁRIO ==
// ATENÇÃO: A função validaUsuario original usava senha em texto plano. Isso é INSEGURO.
// Você DEVE usar password_hash() e password_verify().
// Mantendo a estrutura original por enquanto, mas com aviso.
function validaUsuario($usuario, $senha_plana) // Nome alterado para clareza
{
    if (empty($usuario) || empty($senha_plana)) return false;
    $conn = abreConexaoBD();
    try {
        // BUSCAR PELO USUÁRIO PRIMEIRO
        $sql = "SELECT id_usuario, usuario, senha, tipo_usuario, deletado_usuario FROM usuario WHERE usuario = :usuario"; // Supondo colunas corretas
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':usuario', $usuario);
        $stmt->execute();
        $user_data = $stmt->fetch();

        if ($user_data) {
            // AGORA VERIFICAR A SENHA (DEVERIA SER password_verify)
            // if (password_verify($senha_plana, $user_data['senha'])) { // <-- MÉTODO SEGURO
            if ($senha_plana === $user_data['senha']) { // <-- MÉTODO INSEGURO (EXISTENTE)
                 // Verificar se está ativo (supondo coluna 'deletado_usuario')
                if (isset($user_data['deletado_usuario']) && (int)$user_data['deletado_usuario'] === 0) {
                     unset($user_data['senha']); // Nunca retornar a senha
                     return $user_data;
                }
            }
        }
        return false;
    } catch (PDOException $e) {
        error_log("Erro PDO ao validar usuário {$usuario}: " . $e->getMessage());
        return false; // Falha na validação
    }
}

function logar($usuario, $senha_plana)
{
    $usuarioValidado = validaUsuario($usuario, $senha_plana);
    if ($usuarioValidado) {
        // Idealmente, iniciar sessão PHP ou gerar token JWT aqui
        respondeJson('success', 'Login bem-sucedido!', ['usuario' => $usuarioValidado]);
    } else {
        respondeJson('unauthorized', 'Usuário ou senha inválidos ou conta inativa.'); // Usar 401
    }
}

function criaUsuarios($usuario, $senha_plana) // Deveria receber mais dados
{
    // ATENÇÃO: INSEGURO - Usar password_hash()
    if (empty(trim($usuario)) || empty(trim($senha_plana))) {
         respondeJson('error_client', 'Usuário e senha são obrigatórios.');
    }
    $conn = abreConexaoBD();
    try {
        // $senha_hashed = password_hash($senha_plana, PASSWORD_DEFAULT); // <-- MÉTODO SEGURO
        $sql = "INSERT INTO usuario (usuario, senha) VALUES (:usuario, :senha)"; // Supondo colunas corretas
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':usuario', $usuario);
        $stmt->bindParam(':senha', $senha_plana); // <-- SALVANDO SENHA PLANA (INSEGURO)
        $stmt->execute();
        respondeJson('created', 'Usuário criado com sucesso!', ['id_usuario' => $conn->lastInsertId()]);
    } catch (PDOException $e) {
        error_log("Erro PDO ao criar usuário: " . $e->getMessage());
        if (isset($e->errorInfo[1]) && $e->errorInfo[1] == 1062) { // Chave duplicada
            respondeJson('error_client', 'Erro: Nome de usuário já existe.');
        } else {
            respondeJson('error_server', 'Erro de banco de dados ao criar usuário.');
        }
    }
}

// == MARCA ==
function inserirMarca($nome, $status = 'ativo')
{
    if (empty(trim($nome))) {
        respondeJson('error_client', "O nome da marca é obrigatório.");
    }
    $conn = abreConexaoBD();
    try {
        // Assumindo tabela 'marcas' com colunas 'nome' e 'marca_status'
        $sql = "INSERT INTO marcas (nome, marca_status) VALUES (:nome, :status)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':nome', $nome);
        $stmt->bindParam(':status', $status);
        $stmt->execute();
        respondeJson('created', 'Marca inserida com sucesso!', ['marca_id' => $conn->lastInsertId()]);
    } catch (PDOException $e) {
        error_log("Erro PDO ao inserir marca: " . $e->getMessage());
        if (isset($e->errorInfo[1]) && $e->errorInfo[1] == 1062) {
            respondeJson('error_client', 'Erro: Esta marca já existe.');
        } else {
            respondeJson('error_server', 'Erro de banco de dados ao inserir a marca.');
        }
    }
}

function listarMarcas($page = 1, $limit = 10, $status = 'ativo') // Simplificado, usar versão anterior se precisar de filtro deletado
{
    $conn = abreConexaoBD();
    $page = filter_var($page, FILTER_VALIDATE_INT, ['options' => ['default' => 1, 'min_range' => 1]]);
    $limit = filter_var($limit, FILTER_VALIDATE_INT, ['options' => ['default' => 10, 'min_range' => 1]]);
    $offset = ($page - 1) * $limit;
    try {
        $sql_data = "SELECT marca_id, nome, marca_status FROM marcas WHERE marca_status = :status ORDER BY nome ASC LIMIT :limit OFFSET :offset";
        $stmt_data = $conn->prepare($sql_data);
        $stmt_data->bindParam(':status', $status);
        $stmt_data->bindParam(':limit', $limit, PDO::PARAM_INT);
        $stmt_data->bindParam(':offset', $offset, PDO::PARAM_INT);
        $stmt_data->execute();
        $marcas = $stmt_data->fetchAll();

        $sql_count = "SELECT COUNT(*) FROM marcas WHERE marca_status = :status";
        $stmt_count = $conn->prepare($sql_count);
        $stmt_count->bindParam(':status', $status);
        $stmt_count->execute();
        $total_records = (int)$stmt_count->fetchColumn();

        respondeJson('success', 'Marcas listadas com sucesso.', [
            'data' => $marcas,
            'total' => $total_records,
            'page' => $page,
            'limit' => $limit
        ]);
    } catch (PDOException $e) {
        error_log("Erro PDO ao listar marcas: " . $e->getMessage());
        respondeJson('error_server', 'Erro ao listar marcas.');
    }
}


function atualizarMarca($marca_id, $nome, $status = null)
{
    if (empty($marca_id) || !filter_var($marca_id, FILTER_VALIDATE_INT)) {
         respondeJson('error_client', "ID da marca inválido ou não fornecido.");
    }
     if (empty(trim($nome))) {
        respondeJson('error_client', "O nome da marca é obrigatório.");
    }
    $conn = abreConexaoBD();
    try {
        $fields_to_update = ["nome = :nome"];
        $params = [':marca_id' => (int)$marca_id, ':nome' => $nome];

        if ($status !== null) {
            $fields_to_update[] = "marca_status = :status";
            $params[':status'] = $status;
        }
        // Adicionar lógica para `deletado_marca` se necessário, como na versão anterior.

        $sql = "UPDATE marcas SET " . implode(", ", $fields_to_update) . " WHERE marca_id = :marca_id";
        $stmt = $conn->prepare($sql);
        $stmt->execute($params);

        if ($stmt->rowCount() > 0) {
            respondeJson('success', 'Marca atualizada com sucesso!');
        } else {
             respondeJson('info', 'Nenhuma alteração detectada na marca ou marca não encontrada.');
        }
    } catch (PDOException $e) {
         error_log("Erro PDO ao atualizar marca {$marca_id}: " . $e->getMessage());
        if (isset($e->errorInfo[1]) && $e->errorInfo[1] == 1062) {
            respondeJson('error_client', 'Erro: Já existe outra marca com este nome.');
        } else {
            respondeJson('error_server', 'Erro ao atualizar a marca.');
        }
    }
}


function excluirMarca($marca_id) // ATENÇÃO: Hard delete! A versão anterior fazia Soft Delete.
{
    if (empty($marca_id) || !filter_var($marca_id, FILTER_VALIDATE_INT)) {
        respondeJson('error_client', "ID da marca inválido ou não fornecido.");
    }
    $conn = abreConexaoBD();
    try {
        // Verificar FKs antes se necessário
        $sql = "DELETE FROM marcas WHERE marca_id = :marca_id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':marca_id', $marca_id, PDO::PARAM_INT);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            respondeJson('success', 'Marca excluída com sucesso!');
        } else {
            respondeJson('not_found', 'Marca não encontrada para exclusão.');
        }
     } catch (PDOException $e) {
        error_log("Erro PDO ao excluir marca {$marca_id}: " . $e->getMessage());
        if (isset($e->errorInfo[1]) && ($e->errorInfo[1] == 1451 || $e->errorInfo[1] == 1217)) { // FK constraint
            respondeJson('error_client', 'Erro: Esta marca está associada a outros registros e não pode ser excluída.');
        } else {
            respondeJson('error_server', 'Erro ao excluir a marca.');
        }
    }
}

function carregarMarca($marca_status = 'ativo')
{
    $conn = abreConexaoBD();
    try {
        $sql = "SELECT marca_id, nome, marca_status FROM marcas WHERE marca_status = :status ORDER BY nome ASC";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':status', $marca_status);
        $stmt->execute();
        $marcas = $stmt->fetchAll();
        respondeJson('success', 'Marcas carregadas com sucesso.', ['data' => $marcas]);
    } catch (PDOException $e) {
        error_log("Erro PDO ao carregar marcas: " . $e->getMessage());
        respondeJson('error_server', 'Erro ao carregar marcas.');
    }
}


// == MODELO (NOVAS FUNÇÕES INTEGRADAS) ==
/**
 * Insere um novo modelo no banco de dados.
 */
function inserirModeloPHP($nome_modelo, $cor_modelo, $imagem_modelo_base64, $descricao_modelo = null)
{
    if (empty(trim($nome_modelo)) || empty(trim($cor_modelo)) || empty($imagem_modelo_base64)) {
        respondeJson('error_client', "Nome, Cor e Imagem do modelo são obrigatórios.");
    }
    $conn = abreConexaoBD();
    try {
        $imagemDataBinaria = null;
        if (preg_match('/^data:image\/(\w+);base64,/', $imagem_modelo_base64, $type)) {
            $imagem_modelo_base64 = substr($imagem_modelo_base64, strpos($imagem_modelo_base64, ',') + 1);
        }
        $imagemDataBinaria = base64_decode($imagem_modelo_base64, true);
        if ($imagemDataBinaria === false) {
            respondeJson('error_client', 'A string da imagem (base64) fornecida é inválida ou corrompida.');
        }

        $sql = "INSERT INTO modelo (nome_modelo, cor_modelo, imagem_modelo, descricao_modelo, deletado_modelo)
                VALUES (:nome_modelo, :cor_modelo, :imagem_modelo, :descricao_modelo, 0)";

        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':nome_modelo', $nome_modelo);
        $stmt->bindParam(':cor_modelo', $cor_modelo);
        $desc = $descricao_modelo === '' ? null : $descricao_modelo;
        $stmt->bindParam(':descricao_modelo', $desc, ($desc === null ? PDO::PARAM_NULL : PDO::PARAM_STR));
        $stmt->bindParam(':imagem_modelo', $imagemDataBinaria, PDO::PARAM_LOB);
        $stmt->execute();
        $lastId = $conn->lastInsertId();
        respondeJson('created', 'Modelo inserido com sucesso.', ['id_modelo' => $lastId]);

    } catch (PDOException $e) {
        error_log("Erro PDO ao inserir modelo: " . $e->getMessage());
        if (isset($e->errorInfo[1]) && $e->errorInfo[1] == 1062) {
            respondeJson('error_client', 'Erro: Já existe um modelo com este nome.');
        } else {
            respondeJson('error_server', 'Erro de banco de dados ao inserir o modelo.');
        }
    }
}

/**
 * Lista modelos com paginação e filtro.
 */
function listarModelosPHP($page = 1, $limit = 10, $deletado = 0, $filtro_nome_modelo = null)
{
    $conn = abreConexaoBD();
    $page = filter_var($page, FILTER_VALIDATE_INT, ['options' => ['default' => 1, 'min_range' => 1]]);
    $limit = filter_var($limit, FILTER_VALIDATE_INT, ['options' => ['default' => 10, 'min_range' => 1]]);
    $deletado = filter_var($deletado, FILTER_VALIDATE_INT, ['options' => ['default' => 0, 'min_range' => 0, 'max_range' => 1]]);
    $offset = ($page - 1) * $limit;

    try {
        $sql_base = "SELECT id_modelo, nome_modelo, cor_modelo, descricao_modelo, deletado_modelo FROM modelo";
        $conditions = ["deletado_modelo = :deletado"];
        $params = [':deletado' => $deletado];

        if (!empty(trim($filtro_nome_modelo))) {
            $conditions[] = "nome_modelo LIKE :filtro_nome";
            $params[':filtro_nome'] = "%" . trim($filtro_nome_modelo) . "%";
        }

        $sql_where = !empty($conditions) ? " WHERE " . implode(" AND ", $conditions) : "";

        $sql_data = $sql_base . $sql_where . " ORDER BY nome_modelo ASC LIMIT :limit OFFSET :offset";
        $stmt_data = $conn->prepare($sql_data);

        foreach ($params as $key => &$val) {
            $type = ($key === ':deletado') ? PDO::PARAM_INT : PDO::PARAM_STR;
            $stmt_data->bindParam($key, $val, $type);
        }
        unset($val);
        $stmt_data->bindParam(':limit', $limit, PDO::PARAM_INT);
        $stmt_data->bindParam(':offset', $offset, PDO::PARAM_INT);
        $stmt_data->execute();
        $modelos = $stmt_data->fetchAll();

        $sql_count = "SELECT COUNT(*) FROM modelo" . $sql_where;
        $stmt_count = $conn->prepare($sql_count);
         foreach ($params as $key => &$val) {
            $type = ($key === ':deletado') ? PDO::PARAM_INT : PDO::PARAM_STR;
            $stmt_count->bindParam($key, $val, $type);
        }
        unset($val);
        $stmt_count->execute();
        $total_records = (int)$stmt_count->fetchColumn();

        respondeJson('success', 'Modelos listados com sucesso.', [
            'data' => $modelos, 'total' => $total_records, 'page' => $page, 'limit' => $limit
        ]);

    } catch (PDOException $e) {
        error_log("Erro PDO ao listar modelos: " . $e->getMessage());
        respondeJson('error_server', 'Erro ao listar modelos.');
    }
}

/**
 * Atualiza um modelo existente.
 */
function atualizarModeloPHP($id_modelo, $nome_modelo, $cor_modelo, $descricao_modelo, $imagem_foi_alterada, $imagem_modelo_base64 = null)
{
    if (empty($id_modelo) || !filter_var($id_modelo, FILTER_VALIDATE_INT)) {
        respondeJson('error_client', "ID do modelo inválido ou não fornecido.");
    }
     if (empty(trim($nome_modelo)) || empty(trim($cor_modelo))) {
        respondeJson('error_client', "Nome e Cor do modelo são obrigatórios.");
    }
    $conn = abreConexaoBD();
    try {
        $fields_to_update = []; $params = [':id_modelo' => (int)$id_modelo]; $lob_params = [];
        $fields_to_update[] = "nome_modelo = :nome_modelo"; $params[':nome_modelo'] = $nome_modelo;
        $fields_to_update[] = "cor_modelo = :cor_modelo"; $params[':cor_modelo'] = $cor_modelo;
        $desc = $descricao_modelo === '' ? null : $descricao_modelo;
        $fields_to_update[] = "descricao_modelo = :descricao_modelo"; $params[':descricao_modelo'] = $desc;

        if ($imagem_foi_alterada === true) {
            if (empty($imagem_modelo_base64)) {
                respondeJson('error_client', 'A imagem foi marcada como alterada, mas nenhuma nova imagem foi fornecida.');
            }
            if (preg_match('/^data:image\/(\w+);base64,/', $imagem_modelo_base64, $type)) {
                $imagem_modelo_base64 = substr($imagem_modelo_base64, strpos($imagem_modelo_base64, ',') + 1);
            }
            $imagemDataBinaria = base64_decode($imagem_modelo_base64, true);
            if ($imagemDataBinaria === false) {
                respondeJson('error_client', 'A nova imagem (base64) fornecida é inválida.');
            }
            $fields_to_update[] = "imagem_modelo = :imagem_modelo"; $lob_params[':imagem_modelo'] = $imagemDataBinaria;
        }

        if (empty($fields_to_update)) {
             respondeJson('info', 'Nenhum dado fornecido para atualização.');
        }

        $sql = "UPDATE modelo SET " . implode(", ", $fields_to_update) . " WHERE id_modelo = :id_modelo AND deletado_modelo = 0";
        $stmt = $conn->prepare($sql);
        foreach ($params as $placeholder => $value) {
             $type = PDO::PARAM_STR; if ($placeholder === ':id_modelo') $type = PDO::PARAM_INT; if ($value === null) $type = PDO::PARAM_NULL;
             $stmt->bindValue($placeholder, $value, $type);
        }
        foreach ($lob_params as $placeholder => &$value) { $stmt->bindParam($placeholder, $value, PDO::PARAM_LOB); } unset($value);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            respondeJson('success', 'Modelo atualizado com sucesso!');
        } else {
             $stmt_check = $conn->prepare("SELECT COUNT(*) FROM modelo WHERE id_modelo = :id_modelo"); $stmt_check->execute([':id_modelo' => (int)$id_modelo]);
             if ($stmt_check->fetchColumn() == 0) { respondeJson('not_found', 'Modelo não encontrado para atualização.'); }
             else { respondeJson('info', 'Nenhuma alteração detectada nos dados do modelo.'); }
        }
    } catch (PDOException $e) {
        error_log("Erro PDO ao atualizar modelo {$id_modelo}: " . $e->getMessage());
        if (isset($e->errorInfo[1]) && $e->errorInfo[1] == 1062) { respondeJson('error_client', 'Erro: Já existe outro modelo com este nome.'); }
        else { respondeJson('error_server', 'Erro de banco de dados ao atualizar o modelo.'); }
    }
}

/**
 * Inativa um modelo (soft delete).
 */
function inativarModeloPHP($id_modelo)
{
    if (empty($id_modelo) || !filter_var($id_modelo, FILTER_VALIDATE_INT)) {
        respondeJson('error_client', "ID do modelo inválido ou não fornecido.");
    }
    $conn = abreConexaoBD();
    try {
        $sql = "UPDATE modelo SET deletado_modelo = 1 WHERE id_modelo = :id_modelo AND deletado_modelo = 0";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':id_modelo', $id_modelo, PDO::PARAM_INT);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            respondeJson('success', 'Modelo inativado com sucesso!');
        } else {
             $stmt_check = $conn->prepare("SELECT COUNT(*) FROM modelo WHERE id_modelo = :id_modelo"); $stmt_check->execute([':id_modelo' => $id_modelo]);
             if ($stmt_check->fetchColumn() == 0) { respondeJson('not_found', 'Modelo não encontrado para inativar.'); }
             else { respondeJson('info', 'Modelo já estava inativo.'); }
        }
    } catch (PDOException $e) {
        error_log("Erro PDO ao inativar modelo {$id_modelo}: " . $e->getMessage());
        respondeJson('error_server', 'Erro de banco de dados ao inativar o modelo.');
    }
}

/**
 * Carrega os dados de um modelo específico, incluindo a imagem em Base64.
 */
function carregarModeloPHP($id_modelo)
{
     if (empty($id_modelo) || !filter_var($id_modelo, FILTER_VALIDATE_INT)) {
        respondeJson('error_client', "ID do modelo inválido ou não fornecido.");
    }
    $conn = abreConexaoBD();
    try {
        $sql = "SELECT id_modelo, nome_modelo, cor_modelo, imagem_modelo, descricao_modelo, deletado_modelo FROM modelo WHERE id_modelo = :id_modelo";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':id_modelo', $id_modelo, PDO::PARAM_INT);
        $stmt->execute();
        $modeloData = $stmt->fetch();

        if ($modeloData) {
            if (!empty($modeloData['imagem_modelo'])) {
                $modeloData['imagem_modelo_base64'] = base64_encode($modeloData['imagem_modelo']);
            }
            unset($modeloData['imagem_modelo']);
            respondeJson('success', 'Dados do modelo carregados.', ['data' => $modeloData]);
        } else {
            respondeJson('not_found', 'Modelo não encontrado.');
        }
    } catch (PDOException $e) {
        error_log("Erro PDO ao carregar modelo {$id_modelo}: " . $e->getMessage());
        respondeJson('error_server', 'Erro ao carregar dados do modelo.');
    }
}

/**
 * Exclui um modelo permanentemente do banco de dados (Hard Delete).
 */
function deletarModeloPermanentePHP($id_modelo)
{
    if (empty($id_modelo) || !filter_var($id_modelo, FILTER_VALIDATE_INT)) {
        respondeJson('error_client', "ID do modelo inválido ou não fornecido para exclusão permanente.");
    }
    $conn = abreConexaoBD();
    try {
        // Adicionar verificação de FK se necessário (ver código anterior)
        $sql = "DELETE FROM modelo WHERE id_modelo = :id_modelo";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':id_modelo', $id_modelo, PDO::PARAM_INT);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            respondeJson('success', 'Modelo excluído permanentemente com sucesso!');
        } else {
            respondeJson('not_found', 'Modelo não encontrado para exclusão permanente.');
        }
    } catch (PDOException $e) {
        error_log("Erro PDO ao excluir permanentemente modelo {$id_modelo}: " . $e->getMessage());
        if (isset($e->errorInfo[1]) && ($e->errorInfo[1] == 1451 || $e->errorInfo[1] == 1217)) {
            respondeJson('error_client', 'Erro: Este modelo está referenciado em outra tabela e não pode ser excluído permanentemente.');
        } else {
            respondeJson('error_server', 'Erro de banco de dados ao excluir permanentemente o modelo.');
        }
    }
}

// == PATRIMÔNIO (Funções existentes do seu código original, adaptadas minimamente) ==
// NOTA: A função inserirDados foi mantida como estava, salvando caminho da imagem.
function inserirDados($marca, $modelo, $cor, $codigo, $data, $fotoBase64, $status, $setor, $descricao)
{
    if (empty($marca) || empty($modelo) || empty($cor) || empty($codigo) || empty($data) || empty($status) || empty($setor) || empty($descricao) || empty($fotoBase64)) {
        // Usar respondeJson
        respondeJson('error_client', 'Todos os campos são obrigatórios para inserir patrimônio.');
        return; // Embora respondeJson já tenha exit
    }

    $conn = abreConexaoBD();
    $fotoNome = uniqid() . '.png'; // Ou outra extensão baseada no tipo de imagem
    $diretorioImagens = __DIR__ . '/imagens'; // Usar diretório absoluto
    $fotoCaminho = $diretorioImagens . '/' . $fotoNome;
    $fotoCaminhoRelativo = 'imagens/' . $fotoNome; // Caminho a ser salvo no DB

    if (!file_exists($diretorioImagens)) {
        if (!mkdir($diretorioImagens, 0777, true)) {
             respondeJson('error_server', 'Falha ao criar diretório de imagens.');
        }
    }

    // Decodificar Base64 (sem remover header aqui, pois file_put_contents pode lidar com isso, mas idealmente remover)
     if (preg_match('/^data:image\/(\w+);base64,/', $fotoBase64, $type)) {
        $fotoBase64 = substr($fotoBase64, strpos($fotoBase64, ',') + 1);
     }
    $decoded_image = base64_decode($fotoBase64, true);
    if ($decoded_image === false) {
         respondeJson('error_client', 'Imagem Base64 inválida.');
    }
    if (!file_put_contents($fotoCaminho, $decoded_image)) {
         respondeJson('error_server', 'Falha ao salvar arquivo de imagem.');
    }


    // Assumindo tabela 'patrimonio' com colunas correspondentes
    $sql = "INSERT INTO patrimonio (marca, modelo, cor, codigo, data, imagem, status, setor, descricao)
            VALUES (:marca, :modelo, :cor, :codigo, :data, :imagem, :status, :setor, :descricao)";
    try {
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':marca', $marca);
        $stmt->bindParam(':modelo', $modelo);
        $stmt->bindParam(':cor', $cor);
        $stmt->bindParam(':codigo', $codigo);
        $stmt->bindParam(':data', $data);
        $stmt->bindParam(':imagem', $fotoCaminhoRelativo); // Salva o caminho relativo
        $stmt->bindParam(':status', $status);
        $stmt->bindParam(':setor', $setor);
        $stmt->bindParam(':descricao', $descricao);
        $stmt->execute();
        respondeJson('created', 'Dados do patrimônio inseridos com sucesso.', ['id_patrimonio' => $conn->lastInsertId()]);
    } catch (PDOException $e) {
        error_log("Erro PDO ao inserir patrimônio (inserirDados): " . $e->getMessage());
        // Remover arquivo se a inserção no DB falhar?
        if (file_exists($fotoCaminho)) unlink($fotoCaminho);
        respondeJson('error_server', 'Erro de banco de dados ao inserir o patrimônio.');
    }
}

function listaTodosProdutos() // Renomeado para clareza no roteador
{
    $conn = abreConexaoBD();
    try {
        // Ajustar query para ser mais específica e eficiente se necessário
        $sql = "SELECT * FROM patrimonio ORDER BY id DESC"; // Adicionado ORDER BY exemplo
        $stmt = $conn->query($sql); // Query simples pode usar query()
        $produtos = $stmt->fetchAll();

        // Não há paginação nesta versão, retorna todos. Considere adicionar.
        respondeJson('success', 'Patrimônios listados com sucesso.', ['data' => $produtos ?: []]);
    } catch (PDOException $e) {
        error_log("Erro PDO ao listar patrimônios (listaTodosProdutos): " . $e->getMessage());
        respondeJson('error_server', 'Erro ao listar patrimônios.');
    }
}

function alteraPatrimonio($data) // Mantido, mas atenção aos campos e imagem
{
    $conn = abreConexaoBD();
    $id = $data['id'] ?? null;
    // Extrair outros campos... (marca, modelo, etc.)
    $marca = $data['marca'] ?? null;
    $modelo = $data['modelo'] ?? null;
    // ... garantir que todas as chaves existam ou usar null coalescing
    $fotoBase64 = $data['foto'] ?? null;

    if (empty($id) || !filter_var($id, FILTER_VALIDATE_INT)) {
        respondeJson('error_client', 'ID do patrimônio inválido ou não fornecido.');
    }

    try {
        // Verificar se existe
        $stmt_check = $conn->prepare("SELECT imagem FROM patrimonio WHERE id = :id");
        $stmt_check->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt_check->execute();
        $patrimonioExistente = $stmt_check->fetch();

        if (!$patrimonioExistente) {
            respondeJson('not_found', 'Patrimônio não encontrado.');
        }
        $imagemAntigaPath = $patrimonioExistente['imagem']; // Caminho relativo

        // Montar query dinâmica
        $fields_to_update = []; $params = [':id' => (int)$id]; $newImagePathRel = null;

        if (isset($data['marca'])) { $fields_to_update[] = "marca = :marca"; $params[':marca'] = $data['marca']; }
        if (isset($data['modelo'])) { $fields_to_update[] = "modelo = :modelo"; $params[':modelo'] = $data['modelo']; }
        // ... adicionar todos os outros campos (cor, codigo, data, status, setor, descricao)
        if (isset($data['cor'])) { $fields_to_update[] = "cor = :cor"; $params[':cor'] = $data['cor']; }
        if (isset($data['codigo'])) { $fields_to_update[] = "codigo = :codigo"; $params[':codigo'] = $data['codigo']; }
        if (isset($data['data'])) { $fields_to_update[] = "data = :data"; $params[':data'] = $data['data']; }
        if (isset($data['status'])) { $fields_to_update[] = "status = :status"; $params[':status'] = $data['status']; }
        if (isset($data['setor'])) { $fields_to_update[] = "setor = :setor"; $params[':setor'] = $data['setor']; }
        if (isset($data['descricao'])) { $fields_to_update[] = "descricao = :descricao"; $params[':descricao'] = $data['descricao']; }


        // Tratar imagem SE enviada
        if (!empty($fotoBase64)) {
            if (preg_match('/^data:image\/(\w+);base64,/', $fotoBase64, $type)) {
                $fotoBase64 = substr($fotoBase64, strpos($fotoBase64, ',') + 1);
            }
            $decoded_image = base64_decode($fotoBase64, true);
            if ($decoded_image === false) {
                 respondeJson('error_client', 'Nova imagem Base64 inválida.');
            }
            $fotoNome = uniqid() . '.png';
            $diretorioImagens = __DIR__ . '/imagens';
            $fotoCaminho = $diretorioImagens . '/' . $fotoNome;
            $newImagePathRel = 'imagens/' . $fotoNome; // Novo caminho relativo

            if (!file_exists($diretorioImagens)) { mkdir($diretorioImagens, 0777, true); }
            if (!file_put_contents($fotoCaminho, $decoded_image)) {
                respondeJson('error_server', 'Falha ao salvar novo arquivo de imagem.');
            }
            $fields_to_update[] = "imagem = :imagem"; $params[':imagem'] = $newImagePathRel;
        }

        if (empty($fields_to_update)) {
             respondeJson('info', 'Nenhum dado fornecido para atualização.');
        }

        $sql = "UPDATE patrimonio SET " . implode(", ", $fields_to_update) . " WHERE id = :id";
        $stmt = $conn->prepare($sql);
        $stmt->execute($params); // PDO pode receber array no execute para bindValue

        if ($stmt->rowCount() > 0) {
            // Se a imagem foi atualizada, remover a antiga (opcional)
            if ($newImagePathRel !== null && !empty($imagemAntigaPath) && file_exists(__DIR__ . '/' . $imagemAntigaPath)) {
                unlink(__DIR__ . '/' . $imagemAntigaPath);
            }
            respondeJson('success', 'Dados do patrimônio atualizados com sucesso.');
        } else {
            respondeJson('info', 'Nenhuma alteração detectada nos dados do patrimônio.');
        }
    } catch (PDOException $e) {
        error_log("Erro PDO ao alterar patrimônio {$id}: " . $e->getMessage());
        respondeJson('error_server', 'Erro de banco de dados ao alterar o patrimônio.');
    }
}


function apagaDadosPatrimonio($id) // ATENÇÃO: Hard delete!
{
    if (empty($id) || !filter_var($id, FILTER_VALIDATE_INT)) {
        respondeJson('error_client', "ID do patrimônio inválido ou não fornecido.");
    }
    $conn = abreConexaoBD();
    try {
         // Opcional: Buscar caminho da imagem para deletar o arquivo
        $stmt_getimg = $conn->prepare("SELECT imagem FROM patrimonio WHERE id = :id");
        $stmt_getimg->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt_getimg->execute();
        $imgPathRel = $stmt_getimg->fetchColumn();


        $sql = "DELETE FROM patrimonio WHERE id = :id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            // Deletar arquivo de imagem associado se existir
             if ($imgPathRel && file_exists(__DIR__ . '/' . $imgPathRel)) {
                unlink(__DIR__ . '/' . $imgPathRel);
            }
            respondeJson('success', 'Patrimônio excluído com sucesso.');
        } else {
            respondeJson('not_found', 'Patrimônio não encontrado para exclusão.');
        }
    } catch (PDOException $e) {
        error_log("Erro PDO ao excluir patrimônio {$id}: " . $e->getMessage());
         respondeJson('error_server', 'Erro ao excluir o patrimônio.');
    }
}

function descartarProduto($id) // Atualiza status
{
     if (empty($id) || !filter_var($id, FILTER_VALIDATE_INT)) {
        respondeJson('error_client', "ID do patrimônio inválido ou não fornecido.");
    }
    $conn = abreConexaoBD();
    try {
        $sql = "UPDATE patrimonio SET status = 'descartado' WHERE id = :id"; // Status fixo
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt->execute();
        if ($stmt->rowCount() > 0) {
            respondeJson('success', 'Status do patrimônio atualizado para descartado.');
        } else {
             respondeJson('not_found', 'Patrimônio não encontrado ou já estava descartado.');
        }
    } catch (PDOException $e) {
        error_log("Erro PDO ao descartar patrimônio {$id}: " . $e->getMessage());
        respondeJson('error_server', 'Erro ao atualizar status do patrimônio.');
    }
}

function atualizarStatus($id, $status) // Função específica para status
{
     if (empty($id) || !filter_var($id, FILTER_VALIDATE_INT) || empty(trim($status))) {
        respondeJson('error_client', "ID e Status são obrigatórios e não podem ser vazios.");
    }
     $conn = abreConexaoBD();
    try {
        $sql = "UPDATE patrimonio SET status = :status WHERE id = :id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt->bindParam(':status', $status);
        $stmt->execute();
         if ($stmt->rowCount() > 0) {
            respondeJson('success', 'Status do patrimônio atualizado com sucesso.');
        } else {
             respondeJson('not_found', 'Patrimônio não encontrado ou status já era o mesmo.');
        }
    } catch (PDOException $e) {
        error_log("Erro PDO ao atualizar status do patrimônio {$id}: " . $e->getMessage());
        respondeJson('error_server', 'Erro ao atualizar status do patrimônio.');
    }
}

function buscaResumoPatrimonio()
{
    $conn = abreConexaoBD();
    try {
        $sql = "SELECT status, COUNT(*) as total FROM patrimonio GROUP BY status";
        $stmt = $conn->query($sql);
        $resumo = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);

        // Formatar para garantir chaves e valores como string (como no original)
        $contadoresFormatados = [
            'descartado' => isset($resumo['descartado']) ? (string)$resumo['descartado'] : '0',
            'Emprestado' => isset($resumo['Emprestado']) ? (string)$resumo['Emprestado'] : '0',
            'Usando' => isset($resumo['Usando']) ? (string)$resumo['Usando'] : '0',
             // Adicionar outros status se necessário, com valor default '0'
             'Disponível' => isset($resumo['Disponível']) ? (string)$resumo['Disponível'] : '0',
             'Em manutenção' => isset($resumo['Em manutenção']) ? (string)$resumo['Em manutenção'] : '0',
        ];

        respondeJson('success', 'Resumo do patrimônio carregado.', ['data' => $contadoresFormatados]);

    } catch (PDOException $e) {
        error_log("Erro PDO ao buscar resumo do patrimônio: " . $e->getMessage());
        respondeJson('error_server', 'Erro ao buscar resumo do patrimônio.');
    }
}


// --- ROTEADOR PRINCIPAL ---

// Tratar requisição OPTIONS para CORS preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204); // No Content
    exit;
}

// Verificar se é POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respondeJson('method_not_allowed', 'Método de requisição não suportado. Use POST.');
}

// Ler e decodificar corpo da requisição JSON
$data = json_decode(file_get_contents("php://input"), true);

// Validar JSON e obter ação
if (json_last_error() !== JSON_ERROR_NONE) {
    respondeJson('error_client', 'Corpo da requisição não é um JSON válido.');
}
$acao = $data['acao'] ?? null;
if (!$acao) {
     respondeJson('error_client', 'Ação não especificada na requisição.');
}

// Log da ação e dados recebidos (para depuração)
file_put_contents('debug.txt', "Ação: $acao | Dados: " . json_encode($data) . "\n", FILE_APPEND);


// Lista de ações válidas (incluindo Modelo)
$acoes_validas = [
    // Usuário
    'logar', 'criaUsuarios',
    // Marca
    'inserirMarca', 'listarMarcas', 'atualizarMarca', 'excluirMarca', 'carregarMarca',
    // Modelo (NOVAS)
    'inserirModelo', 'listarModelo', 'atualizarModelo', 'inativarModelo', 'carregarModelo', 'deletarModeloPermanente',
    // Setor
    'inserirSetor', // Adicionar outras se existirem
    // Patrimônio (Nomes antigos mantidos se necessário, mas idealmente renomear)
    'inserir', // <- Ação antiga para inserirPatrimonio (via inserirDados)
    'listar', // <- Ação antiga para listarPatrimonios (via listaTodosProdutos)
    'altera', // <- Ação antiga para alterarPatrimonio
    'descartar', // <- Ação antiga para descartarProduto
    'excluir', // <- Ação antiga para apagaDadosPatrimonio
    'atualizarStatus', // <- Ação antiga para atualizarStatus (específico)
    'buscaResumoPatrimonio',
];

// Validar ação
if (!in_array($acao, $acoes_validas)) {
    respondeJson('error_client', 'Ação inválida ou desconhecida.', ['acao_recebida' => $acao]);
}

// Executar ação correspondente
try {
    switch ($acao) {
        // --- Usuário ---
        case 'logar':
            logar($data['usuario'] ?? null, $data['senha'] ?? null); // Assume chaves 'usuario', 'senha'
            break;
        case 'criaUsuarios':
            criaUsuarios($data['usuario'] ?? null, $data['senha'] ?? null);
            break;

        // --- Marca ---
        case 'inserirMarca':
            inserirMarca($data['nome'] ?? null, $data['status'] ?? 'ativo');
            break;
        case 'listarMarcas':
            listarMarcas($data['page'] ?? 1, $data['limit'] ?? 10, $data['status'] ?? 'ativo');
            break;
        case 'atualizarMarca':
            atualizarMarca($data['marca_id'] ?? null, $data['nome'] ?? null, $data['status'] ?? null);
            break;
        case 'excluirMarca': // Hard delete nesta versão
            excluirMarca($data['marca_id'] ?? null);
            break;
        case 'carregarMarca':
            carregarMarca($data['marca_status'] ?? 'ativo');
            break;

        // --- Modelo (NOVOS CASES) ---
        case 'inserirModelo':
            inserirModeloPHP(
                $data['nome_modelo'] ?? null,
                $data['cor_modelo'] ?? null,
                $data['imagem_modelo_base64'] ?? null,
                $data['descricao_modelo'] ?? null
            );
            break;
        case 'listarModelo':
            listarModelosPHP(
                $data['page'] ?? 1,
                $data['limit'] ?? 10,
                $data['deletado'] ?? 0,
                $data['filtro_nome_modelo'] ?? null
            );
            break;
         case 'atualizarModelo':
             atualizarModeloPHP(
                 $data['id_modelo'] ?? null,
                 $data['nome_modelo'] ?? null,
                 $data['cor_modelo'] ?? null,
                 $data['descricao_modelo'] ?? null,
                 $data['imagem_foi_alterada'] ?? false,
                 $data['imagem_modelo_base64'] ?? null
             );
             break;
         case 'inativarModelo': // Soft delete
             inativarModeloPHP($data['id_modelo'] ?? null);
             break;
        case 'carregarModelo':
             carregarModeloPHP($data['id_modelo'] ?? null);
             break;
        case 'deletarModeloPermanente': // Hard delete
            deletarModeloPermanentePHP($data['id_modelo'] ?? null);
            break;

        // --- Setor ---
        case 'inserirSetor': // Implementar funções de setor se necessário
             respondeJson('info', 'Ação inserirSetor não implementada completamente.'); // Exemplo
            // inserirSetor($data['nomeSetor'] ?? null, ...);
            break;

        // --- Patrimônio (Usando nomes de ações antigos do seu código) ---
        case 'inserir': // Chama inserirDados (salva caminho da imagem)
            inserirDados(
                $data['marca'] ?? null, // Chave diferente aqui ('marca' vs 'marca_id')
                $data['modelo'] ?? null, // Nome do modelo, não ID
                $data['cor'] ?? null,
                $data['codigo'] ?? null,
                $data['data'] ?? null,
                $data['foto'] ?? null, // Chave 'foto' para base64
                $data['status'] ?? null,
                $data['setor'] ?? null, // Nome do setor, não ID
                $data['descricao'] ?? null
            );
            break;
        case 'listar': // Chama listaTodosProdutos
            listaTodosProdutos();
            break;
        case 'altera': // Chama alteraPatrimonio
            alteraPatrimonio($data); // Passa o array $data inteiro
            break;
        case 'descartar': // Chama descartarProduto
            descartarProduto($data['id'] ?? null);
            break;
        case 'excluir': // Chama apagaDadosPatrimonio (Hard delete nesta versão)
            apagaDadosPatrimonio($data['id'] ?? null);
            break;
        case 'atualizarStatus': // Chama função específica atualizarStatus
             atualizarStatus($data['id'] ?? null, $data['status'] ?? null);
            break;
        case 'buscaResumoPatrimonio':
            buscaResumoPatrimonio();
            break;

        // --- Default ---
        default:
            respondeJson('error_client', 'Ação não implementada ou inválida após verificação.'); // Segurança
    }
} catch (PDOException $e) {
    error_log("Erro PDO Geral: " . $e->getMessage() . " | Ação: " . ($acao ?? 'N/A') . " | Dados: " . json_encode($data));
    respondeJson('error_server', 'Erro crítico no banco de dados.');
} catch (TypeError $e) {
    error_log("Erro de Tipo Geral: " . $e->getMessage() . " | Ação: " . ($acao ?? 'N/A') . " | Dados: " . json_encode($data));
    respondeJson('error_client', 'Erro nos tipos de dados enviados.');
} catch (Exception $e) {
    error_log("Exceção Geral: " . $e->getMessage() . " | Ação: " . ($acao ?? 'N/A') . " | Dados: " . json_encode($data));
    respondeJson('error_server', 'Erro interno inesperado.');
}

// Nenhuma tag de fechamento ?> é necessária ou recomendada