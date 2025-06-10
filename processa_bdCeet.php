<?php

// --- Configurações de Erro e Cabeçalhos ---
ini_set('display_errors', 0);
error_reporting(E_ALL);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/php_errors.log');


// --- Validação Crítica ---
if (headers_sent($filename, $linenum)) {
    error_log("Headers já enviados em $filename na linha $linenum antes de definir os headers da API.");
    http_response_code(500);
    echo '{"status":"error_server", "message":"Erro interno: Conflito de saída no servidor."}';
    exit;
}


// --- Cabeçalhos CORS e Content-Type ---
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
header('Content-Type: application/json; charset=UTF-8');

// ===================== Função centralizada para retornar JSON
function respondeJson($status, $mensagem, $dados = [])
{
    $response = ['status' => $status, 'message' => $mensagem, 'data' => $dados];
    echo json_encode($response);
    exit; // Certifique-se de que você quer sair após cada resposta
}


// ===================== Função de conexão com o banco
function abreConexaoBD()
{
    $nomeServidor = "localhost";
    $nomeusuarios = "root";
    $senhaAcesso = "";
    $nomeBanco = "cadastro";

    try {
        $conn = new PDO("mysql:host=$nomeServidor;dbname=$nomeBanco;charset=utf8", $nomeusuarios, $senhaAcesso);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        error_log("Conexão com o banco de dados estabelecida com sucesso."); // Log de sucesso
        return $conn;
    } catch (PDOException $e) {
        error_log("Erro na conexão com o banco de dados: " . $e->getMessage()); // Log de falha
        return null;
    }
}


// ==================== Funções para Usuários

function validaUsuarioPHP($nome_usuario_login, $senha_plana) {
    if (empty($nome_usuario_login) || empty($senha_plana)) {
        error_log("Tentativa de login com nome de usuário ou senha vazios. Usuário: [{$nome_usuario_login}], Senha fornecida: [{$senha_plana}]");
        return false;
    }

    $conn = abreConexaoBD();
    if ($conn === null) {
        error_log("Falha ao conectar ao BD em validaUsuarioPHP.");
        return false;
    }

    try {
        error_log("validaUsuarioPHP: Buscando usuário '{$nome_usuario_login}' no banco.");
        $sql = "SELECT id_usuario, nome_usuario, senha_usuario, cpf_usuario, nasc_usuario, tipo_usuario, deletado_usuario FROM usuario WHERE nome_usuario = :nome_usuario_login";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':nome_usuario_login', $nome_usuario_login, PDO::PARAM_STR);
        $stmt->execute();
        $user_data = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user_data) {
            error_log("validaUsuarioPHP: Usuário '{$nome_usuario_login}' encontrado. Dados: " . print_r($user_data, true));

            if (isset($user_data['deletado_usuario']) && (int)$user_data['deletado_usuario'] === 0) {
                error_log("validaUsuarioPHP: Usuário '{$nome_usuario_login}' está ativo (deletado_usuario = 0).");
                error_log("validaUsuarioPHP: Verificando senha (TEXTO PURO). Senha fornecida: [{$senha_plana}]. Senha no DB: [{$user_data['senha_usuario']}]");

                // ***** COMPARAÇÃO DIRETA DE TEXTO PURO *****
                if ($senha_plana === $user_data['senha_usuario']) {
                // ****************************************
                    error_log("validaUsuarioPHP: Senha em TEXTO PURO verificada com sucesso para '{$nome_usuario_login}'.");
                    unset($user_data['senha_usuario']);
                    $user_data['id_usuario'] = (int)$user_data['id_usuario'];
                    $user_data['deletado_usuario'] = (int)$user_data['deletado_usuario'];
                    return $user_data;
                } else {
                    error_log("Tentativa de login falhou para usuário '{$nome_usuario_login}': senha incorreta (comparação de texto puro falhou).");
                }
            } else {
                error_log("Tentativa de login falhou para usuário '{$nome_usuario_login}': conta inativa (deletado_usuario = {$user_data['deletado_usuario']}).");
            }
        } else {
            error_log("Tentativa de login falhou: usuário '{$nome_usuario_login}' não encontrado no banco de dados.");
        }
        return false;
    } catch (PDOException $e) {
        error_log("Erro PDO ao validar usuário {$nome_usuario_login}: " . $e->getMessage());
        return false;
    } finally {
        $conn = null;
    }
}

function logarPHP($nome_usuario_login, $senha_plana) {
    // Adiciona logs para ver o que está sendo recebido
    error_log("logarPHP: Recebido nome_usuario_login: [{$nome_usuario_login}], senha_plana: [{$senha_plana}]");

    $usuarioValidado = validaUsuarioPHP($nome_usuario_login, $senha_plana);
    if ($usuarioValidado) {
        respondeJson('success', 'Login bem-sucedido!', ['usuario' => $usuarioValidado]);
    } else {
        respondeJson('unauthorized', 'Nome de usuário ou senha inválidos, ou conta inativa.');
    }
}

function inserirUsuarioCompletoPHP($nome_usuario, $senha_plana, $cpf_usuario, $nasc_usuario_str, $tipo_usuario) {
    // Validação de campos obrigatórios
    if (empty(trim($nome_usuario)) || empty(trim($senha_plana)) || empty(trim($cpf_usuario)) || empty(trim($nasc_usuario_str)) || empty(trim($tipo_usuario))) {
        respondeJson('error_client', 'Todos os campos obrigatórios (Nome, Senha, CPF, Data de Nascimento, Tipo) são obrigatórios para cadastro.');
    }

    // Validar formato da data (YYYY-MM-DD)
    if (!preg_match("/^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])$/", $nasc_usuario_str)) {
        respondeJson('error_client', 'Formato da data de nascimento inválido. Use YYYY-MM-DD.');
    }
    // TODO: Adicionar validação de CPF aqui se desejado (ex: comprimento, dígitos, validação de soma)

    $conn = abreConexaoBD();
    if ($conn === null) {
        respondeJson('error_server', 'Não foi possível conectar ao banco de dados para inserir o usuário.');
    }

    try {
        $senha_hashed = password_hash($senha_plana, PASSWORD_DEFAULT);
        if ($senha_hashed === false) {
            error_log("Falha ao gerar hash da senha para usuário: {$nome_usuario}");
            respondeJson('error_server', 'Falha interna ao processar a senha.');
        }

        // Removido 'email_usuario' da instrução SQL
        $sql = "INSERT INTO usuario (nome_usuario, senha_usuario, cpf_usuario, nasc_usuario, tipo_usuario, deletado_usuario)
                VALUES (:nome_usuario, :senha_usuario, :cpf_usuario, :nasc_usuario, :tipo_usuario, 0)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':nome_usuario', $nome_usuario, PDO::PARAM_STR);
        $stmt->bindParam(':senha_usuario', $senha_hashed, PDO::PARAM_STR);
        $stmt->bindParam(':cpf_usuario', $cpf_usuario, PDO::PARAM_STR);
        $stmt->bindParam(':nasc_usuario', $nasc_usuario_str, PDO::PARAM_STR);
        $stmt->bindParam(':tipo_usuario', $tipo_usuario, PDO::PARAM_STR);
        $stmt->execute();
        $id_novo_usuario = $conn->lastInsertId();

        $usuario_criado = [
            'id_usuario' => (int)$id_novo_usuario,
            'nome_usuario' => $nome_usuario,
            'cpf_usuario' => $cpf_usuario,
            'nasc_usuario' => $nasc_usuario_str,
            'tipo_usuario' => $tipo_usuario,
            'deletado_usuario' => 0
        ];
        respondeJson('created', 'Usuário criado com sucesso!', ['usuario' => $usuario_criado]);

    } catch (PDOException $e) {
        error_log("Erro PDO ao criar usuário completo ({$nome_usuario}): " . $e->getMessage());
        if (isset($e->errorInfo[1]) && $e->errorInfo[1] == 1062) { // Código de erro para chave duplicada
            if (strpos(strtolower($e->getMessage()), 'cpf_usuario') !== false) {
                respondeJson('error_client', 'Erro: CPF já cadastrado.');
            } else {
                respondeJson('error_client', 'Erro: Já existe um usuário com um dos dados únicos fornecidos.');
            }
        } else {
            respondeJson('error_server', 'Erro de banco de dados ao tentar criar o usuário.');
        }
    } finally {
        $conn = null;
    }
}


function listarUsuariosPHP($deletado = 0, $filtro_nome_usuario = null) {
    $conn = abreConexaoBD();
    if ($conn === null) {
        respondeJson('error_server', 'Não foi possível conectar ao banco de dados.');
    }

    try {
        // Removido 'email_usuario' do SELECT
        $sql_base = "SELECT id_usuario, nome_usuario, cpf_usuario, nasc_usuario, tipo_usuario, deletado_usuario FROM usuario";
        $conditions = ["deletado_usuario = :deletado_filter"];
        $params = [':deletado_filter' => (int)$deletado];

        if (!empty(trim($filtro_nome_usuario))) {
            $conditions[] = "nome_usuario LIKE :filtro_nome";
            $params[':filtro_nome'] = "%" . trim($filtro_nome_usuario) . "%";
        }

        $sql_where = !empty($conditions) ? " WHERE " . implode(" AND ", $conditions) : "";
        $sql_data = $sql_base . $sql_where . " ORDER BY nome_usuario ASC";
        $stmt_data = $conn->prepare($sql_data);

        foreach ($params as $key => &$val) {
            $type = ($key === ':deletado_filter') ? PDO::PARAM_INT : PDO::PARAM_STR;
            $stmt_data->bindParam($key, $val, $type);
        }
        unset($val); // Desreferencia a variável para evitar problemas em loops

        $stmt_data->execute();
        $usuarios = $stmt_data->fetchAll(PDO::FETCH_ASSOC);

        // Garante que 'id_usuario' e 'deletado_usuario' sejam inteiros
        $usuarios = array_map(function($user) {
            $user['id_usuario'] = (int)$user['id_usuario'];
            $user['deletado_usuario'] = (int)$user['deletado_usuario'];
            return $user;
        }, $usuarios);

        respondeJson('success', 'Usuários listados com sucesso.', $usuarios ?: []);

    } catch (PDOException $e) {
        error_log("Erro PDO ao listar usuários: " . $e->getMessage());
        respondeJson('error_server', 'Erro de banco de dados ao listar usuários.');
    } finally {
        $conn = null;
    }
}


function atualizarUsuarioCompletoPHP($id_usuario, $dados_update) {
    if (empty($id_usuario) || !filter_var($id_usuario, FILTER_VALIDATE_INT)) {
        respondeJson('error_client', "ID do usuário inválido ou não fornecido para atualização.");
    }

    $conn = abreConexaoBD();
    if ($conn === null) {
        respondeJson('error_server', 'Não foi possível conectar ao banco de dados para atualizar o usuário.');
    }

    try {
        $fields_to_update = [];
        $params = [':id_usuario' => (int)$id_usuario];

        // Seus campos existentes
        if (isset($dados_update['nome_usuario']) && !empty(trim($dados_update['nome_usuario']))) {
            $fields_to_update[] = "nome_usuario = :nome_usuario";
            $params[':nome_usuario'] = trim($dados_update['nome_usuario']);
        }
        if (isset($dados_update['cpf_usuario']) && !empty(trim($dados_update['cpf_usuario']))) {
            $fields_to_update[] = "cpf_usuario = :cpf_usuario";
            $params[':cpf_usuario'] = trim($dados_update['cpf_usuario']);
        }
        if (isset($dados_update['nasc_usuario']) && !empty(trim($dados_update['nasc_usuario']))) {
            if (!preg_match("/^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])$/", $dados_update['nasc_usuario'])) {
                respondeJson('error_client', 'Formato da data de nascimento inválido para atualização. Use YYYY-MM-DD.');
            }
            $fields_to_update[] = "nasc_usuario = :nasc_usuario";
            $params[':nasc_usuario'] = $dados_update['nasc_usuario'];
        }
        if (isset($dados_update['tipo_usuario']) && !empty(trim($dados_update['tipo_usuario']))) {
            $fields_to_update[] = "tipo_usuario = :tipo_usuario";
            $params[':tipo_usuario'] = trim($dados_update['tipo_usuario']);
        }

        // Se uma nova senha foi fornecida
        if (isset($dados_update['senha_usuario']) && !empty(trim($dados_update['senha_usuario']))) {
            $senha_hashed = password_hash(trim($dados_update['senha_usuario']), PASSWORD_DEFAULT);
            if ($senha_hashed === false) {
                error_log("Falha ao gerar hash da nova senha para usuário ID: {$id_usuario}");
                respondeJson('error_server', 'Falha interna ao processar a nova senha.');
            }
            $fields_to_update[] = "senha_usuario = :senha_usuario";
            $params[':senha_usuario'] = $senha_hashed;
        }

        // Campo deletado_usuario pode ser atualizado para ativar/desativar
        if (isset($dados_update['deletado_usuario'])) {
            $fields_to_update[] = "deletado_usuario = :deletado_usuario";
            $params[':deletado_usuario'] = (int)$dados_update['deletado_usuario'];
        }

        if (empty($fields_to_update)) {
            respondeJson('info', 'Nenhum dado válido fornecido para atualização do usuário.');
        }

        $sql = "UPDATE usuario SET " . implode(", ", $fields_to_update) . " WHERE id_usuario = :id_usuario";
        $stmt = $conn->prepare($sql);
        $stmt->execute($params);

        if ($stmt->rowCount() > 0) {
            respondeJson('success', 'Usuário atualizado com sucesso!');
        } else {
            $stmt_check = $conn->prepare("SELECT COUNT(*) FROM usuario WHERE id_usuario = :id_chk");
            $stmt_check->execute([':id_chk' => (int)$id_usuario]);
            if ($stmt_check->fetchColumn() == 0) {
                respondeJson('not_found', 'Usuário não encontrado para atualização.');
            } else {
                respondeJson('info', 'Nenhuma alteração detectada nos dados do usuário (ou dados eram os mesmos).');
            }
        }
    } catch (PDOException $e) {
        error_log("API ERRO: PDO ao atualizar usuário ID {$id_usuario}: " . $e->getMessage());
        if (isset($e->errorInfo[1]) && $e->errorInfo[1] == 1062) { // Código de erro para chave duplicada (CPF)
            if (strpos(strtolower($e->getMessage()), 'cpf_usuario') !== false) {
                respondeJson('error_client', 'Erro: CPF já cadastrado para outro usuário.');
            } else {
                respondeJson('error_client', 'Erro: Já existe outro usuário com um dos dados únicos fornecidos.');
            }
        } else {
            respondeJson('error_server', 'Erro de banco de dados ao tentar atualizar o usuário.');
        }
    } finally {
        $conn = null;
    }
}

function inativarUsuarioPHP($id_usuario) {
    if (empty($id_usuario) || !filter_var($id_usuario, FILTER_VALIDATE_INT)) {
        respondeJson('error_client', "ID do usuário inválido ou não fornecido.");
    }
    $conn = abreConexaoBD();
    if ($conn === null) {
        respondeJson('error_server', 'Não foi possível conectar ao banco de dados para inativar o usuário.');
    }

    try {
        $sql = "UPDATE usuario SET deletado_usuario = 1 WHERE id_usuario = :id_usuario AND deletado_usuario = 0";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':id_usuario', $id_usuario, PDO::PARAM_INT);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            respondeJson('success', 'Usuário inativado com sucesso!');
        } else {
            $stmt_check = $conn->prepare("SELECT deletado_usuario FROM usuario WHERE id_usuario = :id_usuario_check");
            $stmt_check->execute([':id_usuario_check' => $id_usuario]);
            $status_deletado = $stmt_check->fetchColumn();

            if ($status_deletado === false) {
                respondeJson('not_found', 'Usuário não encontrado para inativar.');
            } elseif ((int)$status_deletado === 1) {
                respondeJson('info', 'Usuário já estava inativo.');
            } else {
                respondeJson('info', 'Nenhuma alteração realizada ao tentar inativar o usuário.');
            }
        }
    } catch (PDOException $e) {
        error_log("Erro PDO ao inativar usuário ID {$id_usuario}: " . $e->getMessage());
        respondeJson('error_server', 'Erro de banco de dados ao inativar o usuário.');
    } finally {
        $conn = null;
    }
}


function carregarUsuarioPHP($id_usuario) {
    if (empty($id_usuario) || !filter_var($id_usuario, FILTER_VALIDATE_INT)) {
        respondeJson('error_client', "ID do usuário inválido ou não fornecido.");
    }
    $conn = abreConexaoBD();
    if ($conn === null) {
        respondeJson('error_server', 'Não foi possível conectar ao banco de dados para carregar o usuário.');
    }

    try {
        // Removido 'email_usuario' do SELECT
        $sql = "SELECT id_usuario, nome_usuario, cpf_usuario, nasc_usuario, tipo_usuario, deletado_usuario FROM usuario WHERE id_usuario = :id_usuario";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':id_usuario', $id_usuario, PDO::PARAM_INT);
        $stmt->execute();
        $usuarioData = $stmt->fetch(PDO::FETCH_ASSOC); // Garante array associativo

        if ($usuarioData) {
            // Garante que 'id_usuario' e 'deletado_usuario' sejam inteiros
            $usuarioData['id_usuario'] = (int)$usuarioData['id_usuario'];
            $usuarioData['deletado_usuario'] = (int)$usuarioData['deletado_usuario'];
            respondeJson('success', 'Dados do usuário carregados com sucesso.', ['data' => $usuarioData]);
        } else {
            respondeJson('not_found', 'Usuário não encontrado.');
        }
    } catch (PDOException $e) {
        error_log("Erro PDO ao carregar usuário ID {$id_usuario}: " . $e->getMessage());
        respondeJson('error_server', 'Erro de banco de dados ao carregar dados do usuário.');
    } finally {
        $conn = null;
    }
}



// ===================== Funções para Modelos
function salvarImagemBase64Modelo($base64String, $diretorioDestino, $prefixoNomeArquivo = 'img_') {
    if (empty($base64String)) return false;
    if (preg_match('/^data:image\/(\w+);base64,/', $base64String, $type)) {
        $base64String = substr($base64String, strpos($base64String, ',') + 1);
        $tipoImagem = strtolower($type[1]);
        if (!in_array($tipoImagem, ['jpeg', 'jpg', 'png', 'gif'])) return false;
        $extensao = '.' . ($tipoImagem == 'jpeg' ? 'jpg' : $tipoImagem);
    } else { $extensao = '.png'; }
    $imagemDataBinaria = base64_decode($base64String, true);
    if ($imagemDataBinaria === false) return false;
    if (!file_exists($diretorioDestino)) { if (!mkdir($diretorioDestino, 0775, true)) return false; }
    $nomeArquivo = uniqid($prefixoNomeArquivo) . $extensao;
    $caminhoCompleto = $diretorioDestino . $nomeArquivo;
    if (file_put_contents($caminhoCompleto, $imagemDataBinaria)) { return UPLOAD_URL_MODELOS . $nomeArquivo; }
    else { return false; }
}

define('UPLOAD_DIR_MODELOS', 'C:\xampp\htdocs\api\imagens\\'); // Barra no final é importante
define('UPLOAD_URL_MODELOS', 'http://192.168.100.47/api/imagens/'); // Ajuste a URL base

function inserirModeloPHP($nome_modelo, $cor_modelo, $descricao_modelo = null) {
    error_log("InserirModeloPHP chamado com: nome=$nome_modelo, cor=$cor_modelo, descricao=$descricao_modelo");

    if (empty(trim($nome_modelo)) || empty(trim($cor_modelo))) {
        respondeJson('error_client', "Nome e Cor do modelo são obrigatórios.");
        return;
    }
    $conn = abreConexaoBD();
    $caminhoImagemRelativo = null;

    error_log("Verificando se o upload de imagem ocorreu sem erros...");
    if (isset($_FILES['imagem_modelo']) && $_FILES['imagem_modelo']['error'] === UPLOAD_ERR_OK) {
        $arquivoTemp = $_FILES['imagem_modelo']['tmp_name'];
        $nomeOriginal = $_FILES['imagem_modelo']['name'];
        $extensao = pathinfo($nomeOriginal, PATHINFO_EXTENSION);
        $nomeArquivoUnico = uniqid('modelo_') . '.' . $extensao;
        $caminhoDestinoCompleto = UPLOAD_DIR_MODELOS . $nomeArquivoUnico;
        $caminhoImagemRelativo = UPLOAD_URL_MODELOS . $nomeArquivoUnico;

        error_log("Arquivo temporário: $arquivoTemp");
        error_log("Caminho de destino: $caminhoDestinoCompleto");

        if (!is_dir(UPLOAD_DIR_MODELOS)) {
            error_log("ERRO: Diretório de upload não existe: " . UPLOAD_DIR_MODELOS);
            respondeJson('error_server', 'Erro: Diretório de upload não encontrado no servidor.');
            return;
        }

        error_log("Tentando mover o arquivo...");
        if (!move_uploaded_file($arquivoTemp, $caminhoDestinoCompleto)) {
            $erro = error_get_last();
            error_log("ERRO ao mover o arquivo para $caminhoDestinoCompleto. Erro PHP: " . print_r($erro, true));
            respondeJson('error_server', 'Falha ao mover a imagem para o servidor.');
            return;
        } else {
            error_log("Arquivo movido com sucesso para: $caminhoDestinoCompleto");
        }
    } else {
        error_log("Nenhuma imagem enviada ou erro no upload. Código de erro: " . ($_FILES['imagem_modelo']['error'] ?? 'nenhum'));
    }

    try {
        $sql = "INSERT INTO modelo (nome_modelo, cor_modelo, imagem_modelo, descricao_modelo, deletado_modelo) VALUES (:nome_modelo, :cor_modelo, :imagem_modelo, :descricao_modelo, 0)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':nome_modelo', $nome_modelo);
        $stmt->bindParam(':cor_modelo', $cor_modelo);
        $desc = $descricao_modelo === '' ? null : $descricao_modelo;
        $stmt->bindParam(':descricao_modelo', $desc, ($desc === null ? PDO::PARAM_NULL : PDO::PARAM_STR));
        $stmt->bindParam(':imagem_modelo', $caminhoImagemRelativo, ($caminhoImagemRelativo === null ? PDO::PARAM_NULL : PDO::PARAM_STR));
        $stmt->execute();
        $lastId = $conn->lastInsertId();
        respondeJson('created', 'Modelo inserido com sucesso.', ['id_modelo' => $lastId, 'imagem_url' => $caminhoImagemRelativo]);
    } catch (PDOException $e) {
        error_log("Erro PDO inserirModelo: " . $e->getMessage());
        if ($caminhoImagemRelativo && file_exists(UPLOAD_DIR_MODELOS . basename($caminhoImagemRelativo))) {
            unlink(UPLOAD_DIR_MODELOS . basename($caminhoImagemRelativo));
        }
        if (isset($e->errorInfo[1]) && $e->errorInfo[1] == 1062) {
            respondeJson('error_client', 'Erro: Já existe um modelo com este nome.');
        } else {
            respondeJson('error_server', 'Erro de banco de dados ao inserir o modelo.');
        }
    }
}

function listarModelosPHP($deletado = 0, $filtro_nome_modelo = null) {
    $conn = abreConexaoBD();
    $deletado = filter_var($deletado, FILTER_VALIDATE_INT, ['options' => ['default' => 0, 'min_range' => 0, 'max_range' => 1]]);
    
    try {
        $sql_base = "SELECT id_modelo, nome_modelo, cor_modelo, descricao_modelo, imagem_modelo, deletado_modelo FROM modelo";
        $conditions = ["deletado_modelo = :deletado"];
        $params = [':deletado' => $deletado];

        if (isset($filtro_nome_modelo) && !empty(trim($filtro_nome_modelo))) {
            $conditions[] = "nome_modelo LIKE :filtro_nome";
            $params[':filtro_nome'] = "%" . trim($filtro_nome_modelo) . "%";
        }

        $sql_where = !empty($conditions) ? " WHERE " . implode(" AND ", $conditions) : "";
        
        // Remove LIMIT e OFFSET daqui
        $sql_data = $sql_base . $sql_where . " ORDER BY nome_modelo ASC";

        $stmt_data = $conn->prepare($sql_data);
        
        // Binda os parâmetros para as condições (deletado, filtro_nome_modelo)
        foreach ($params as $key => &$val) {
            $type = ($key === ':deletado') ? PDO::PARAM_INT : PDO::PARAM_STR;
            $stmt_data->bindParam($key, $val, $type);
        }
        unset($val); // Importante para evitar problemas com bindParam por referência

        $stmt_data->execute();
        $modelos = $stmt_data->fetchAll(PDO::FETCH_ASSOC);

        // O COUNT(*) continua sendo útil para informar o total de registros que correspondem ao filtro,
        // mesmo que você não esteja usando paginação.
        $sql_count = "SELECT COUNT(*) FROM modelo" . $sql_where;
        $stmt_count = $conn->prepare($sql_count);
        foreach ($params as $key => &$val) {
            $type = ($key === ':deletado') ? PDO::PARAM_INT : PDO::PARAM_STR;
            $stmt_count->bindParam($key, $val, $type);
        }
        unset($val);
        $stmt_count->execute();
        $total_records = (int)$stmt_count->fetchColumn();
        
        // Remove 'page' e 'limit' da resposta, ou mantenha-os como valores fixos se a interface cliente esperar
        respondeJson('success', 'Modelos listados.', ['modelos' => $modelos, 'total' => $total_records]); 
        
    } catch (PDOException $e) {
        error_log("Erro PDO listarModelos: " . $e->getMessage());
        respondeJson('error_server', 'Erro ao listar modelos.');
    } finally {
        fechaConexaoBD($conn);
    }
}

function atualizarModeloPHP($id_modelo, $nome_modelo, $cor_modelo, $descricao_modelo) {
    $conn = abreConexaoBD(); // Abre a conexão com o banco de dados

    // Validação inicial do ID do modelo
    $id_modelo_int = filter_var($id_modelo, FILTER_VALIDATE_INT);
    if ($id_modelo_int === false || $id_modelo_int <= 0) {
        respondeJson('error_client', "ID do modelo inválido.");
        return;
    }

    // Validação de campos obrigatórios
    if (empty(trim($nome_modelo)) || empty(trim($cor_modelo))) {
        respondeJson('error_client', "Nome e Cor são obrigatórios.");
        return;
    }

    $caminhoImagemAntigaNoDB = null;     // Caminho da imagem ANTES da atualização no DB (URL)
    $novoCaminhoImagemParaDB = null;     // Caminho da NOVA imagem no DB (URL) (ou NULL se removida, embora não usada no Flutter)
    $shouldUpdateImageColumn = false;    // Indica se a coluna 'imagem_modelo' deve ser incluída no UPDATE

    try {
        // 1. Obter os dados atuais do modelo, incluindo o caminho da imagem e status de inativado
        $stmt_current_data = $conn->prepare("SELECT nome_modelo, cor_modelo, descricao_modelo, imagem_modelo FROM modelo WHERE id_modelo = :id_modelo AND deletado_modelo = 0");
        $stmt_current_data->bindParam(':id_modelo', $id_modelo_int, PDO::PARAM_INT);
        $stmt_current_data->execute();
        $modeloExistente = $stmt_current_data->fetch(PDO::FETCH_ASSOC);

        if (!$modeloExistente) {
            respondeJson('not_found', 'Modelo não encontrado ou inativado.');
            return;
        }
        $caminhoImagemAntigaNoDB = $modeloExistente['imagem_modelo']; // Pode ser NULL

        // Flag para verificar se houveram mudanças nos dados textuais
        $dataChanged = false;
        if ($modeloExistente['nome_modelo'] !== $nome_modelo ||
            $modeloExistente['cor_modelo'] !== $cor_modelo ||
            (trim($modeloExistente['descricao_modelo'] ?? '') !== trim($descricao_modelo ?? '')) ) {
            // Nota: Adicionei (?? '') para lidar com nulls em descricao_modelo de forma segura para trim()
            $dataChanged = true;
        }

        // 2. Lógica de tratamento da IMAGEM
        // 2a. Se uma NOVA imagem foi enviada (Flutter enviou arquivo no campo 'imagem_modelo')
        if (isset($_FILES['imagem_modelo']) && $_FILES['imagem_modelo']['error'] === UPLOAD_ERR_OK) {
            $arquivoTemp = $_FILES['imagem_modelo']['tmp_name'];
            $nomeOriginal = $_FILES['imagem_modelo']['name'];
            $extensao = pathinfo($nomeOriginal, PATHINFO_EXTENSION);
            $nomeArquivoUnico = uniqid('modelo_') . '.' . $extensao;
            $caminhoDestinoCompletoNoServidor = UPLOAD_DIR_MODELOS . $nomeArquivoUnico;
            $novoCaminhoImagemParaDB = UPLOAD_URL_MODELOS . $nomeArquivoUnico; // URL para o DB

            // Cria o diretório se não existir
            if (!is_dir(UPLOAD_DIR_MODELOS)) {
                if (!mkdir(UPLOAD_DIR_MODELOS, 0755, true)) {
                    respondeJson('error_server', 'Falha ao criar diretório de upload.');
                    return;
                }
            }

            if (!move_uploaded_file($arquivoTemp, $caminhoDestinoCompletoNoServidor)) {
                $erro = error_get_last();
                error_log("ERRO ao mover o arquivo na atualização para $caminhoDestinoCompletoNoServidor. Erro PHP: " . print_r($erro, true));
                respondeJson('error_server', 'Falha ao mover a nova imagem para o servidor.');
                return;
            }
            $shouldUpdateImageColumn = true; // Sinaliza que a imagem no DB precisa ser atualizada

            // Excluir a imagem antiga do servidor, se houver e for diferente da nova
            // E se a imagem antiga não for o padrão ou nula
            if ($caminhoImagemAntigaNoDB &&
                // Garante que não estamos tentando apagar uma imagem padrão se você tiver uma
                // E que não estamos tentando apagar a imagem que acabamos de fazer upload (embora raro)
                (basename($caminhoImagemAntigaNoDB) !== 'default.png') &&
                (UPLOAD_DIR_MODELOS . basename($caminhoImagemAntigaNoDB) !== $caminhoDestinoCompletoNoServidor) &&
                file_exists(UPLOAD_DIR_MODELOS . basename($caminhoImagemAntigaNoDB))) {

                unlink(UPLOAD_DIR_MODELOS . basename($caminhoImagemAntigaNoDB));
                error_log("DEBUG: Imagem antiga removida (substituída): " . UPLOAD_DIR_MODELOS . basename($caminhoImagemAntigaNoDB));
            }
        }
        // A lógica de 'imagem_modelo_removida' foi removida, pois seu Flutter não a usa.
        // Se nem nova imagem enviada, nem remoção sinalizada, e a imagem antiga existe,
        // $shouldUpdateImageColumn permanece false, e a coluna de imagem não será alterada no DB,
        // mantendo a imagem existente.
        // Se a imagem antiga era nula e não houve upload/remoção, continua nula.


        // 3. Preparar campos para atualização no banco de dados
        $fields_to_update = [];
        $params = [':id_modelo' => $id_modelo_int]; // Já é inteiro validado

        $fields_to_update[] = "nome_modelo = :nome_modelo";
        $params[':nome_modelo'] = $nome_modelo;

        $fields_to_update[] = "cor_modelo = :cor_modelo";
        $params[':cor_modelo'] = $cor_modelo;

        // Descrição pode ser null
        $desc_final = (trim($descricao_modelo ?? '') === '') ? null : $descricao_modelo; // Trata vazio como null
        $fields_to_update[] = "descricao_modelo = :descricao_modelo";
        $params[':descricao_modelo'] = $desc_final;

        // Incluir o campo da imagem APENAS SE houver uma nova imagem OU se foi sinalizada a remoção
        if ($shouldUpdateImageColumn) {
            $fields_to_update[] = "imagem_modelo = :imagem_modelo";
            $params[':imagem_modelo'] = $novoCaminhoImagemParaDB; // Será o novo caminho (string) ou NULL
        }

        // 4. Construir e executar a query de atualização
        $sql = "UPDATE modelo SET " . implode(", ", $fields_to_update) . " WHERE id_modelo = :id_modelo AND deletado_modelo = 0";
        $stmt = $conn->prepare($sql);
        if (!$stmt) {
            error_log("Erro na preparação da query de atualização: " . implode(" ", $conn->errorInfo()));
            throw new Exception("Erro interno do servidor.");
        }

        // Bind dos parâmetros
        foreach ($params as $placeholder => &$value) {
            $type = PDO::PARAM_STR; // Default para string
            if ($placeholder === ':id_modelo') {
                $type = PDO::PARAM_INT;
            } elseif ($value === null) {
                $type = PDO::PARAM_NULL;
            }
            $stmt->bindParam($placeholder, $value, $type);
        }
        unset($value); // Desfazer a referência após o loop (boa prática para foreach com &)

        $stmt->execute();

        // 5. Tratar o resultado da atualização
        $affectedRows = $stmt->rowCount();

        // Determinar a URL da imagem a ser retornada na resposta
        // Se a coluna da imagem foi atualizada, use o novo caminho. Caso contrário, use o caminho antigo (do DB).
        $imagemUrlRetorno = $shouldUpdateImageColumn ? $novoCaminhoImagemParaDB : $caminhoImagemAntigaNoDB;

        if ($affectedRows > 0) {
            // Se alguma linha foi afetada, é um sucesso (dados textuais ou imagem foram atualizados)
            respondeJson('success', 'Modelo atualizado com sucesso!', ['id_modelo' => $id_modelo_int, 'imagem_url' => $imagemUrlRetorno]);
        } else {
            // Nenhuma linha afetada:
            // Isso acontece se os dados textuais não mudaram E a imagem também não mudou (ou não foi sinalizada para mudança)
            // OU se a imagem foi atualizada, mas os dados textuais não (e o affectedRows pode ser 0 dependendo do PDO/MySQL)
            // A lógica de $shouldUpdateImageColumn já tratou se a imagem foi o único campo a ser alterado.
            if ($dataChanged || $shouldUpdateImageColumn) {
                // Se chegamos aqui e affectedRows é 0, mas sabemos que algo *deveria* ter mudado (dataChanged ou shouldUpdateImageColumn)
                // Isso pode indicar que o PDO/MySQL não reportou affectedRows para a mudança de imagem,
                // ou que o estado anterior e o novo são "iguais" para o DB (ex: descrição de null para '').
                // Neste caso, ainda é um sucesso, pois o que foi solicitado foi "aplicado".
                respondeJson('success', 'Modelo atualizado com sucesso (sem alteração aparente no DB, mas processado)!', ['id_modelo' => $id_modelo_int, 'imagem_url' => $imagemUrlRetorno]);
            } else {
                // Nenhuma alteração textual e nenhuma alteração de imagem.
                // IMPORTANTE: Inclua 'data' com a imagem_url atual do modelo para evitar TypeError no Flutter.
                respondeJson('info', 'Nenhuma alteração detectada nos dados do modelo.', ['id_modelo' => $id_modelo_int, 'imagem_url' => $imagemUrlRetorno]);
            }
        }

    } catch (PDOException $e) {
        error_log("Erro PDO ao atualizar modelo {$id_modelo_int}: " . $e->getMessage());
        // Se houve um erro de DB APÓS o upload da nova imagem, exclua a nova imagem "órfã".
        if ($novoCaminhoImagemParaDB && file_exists(UPLOAD_DIR_MODELOS . basename($novoCaminhoImagemParaDB))) {
            unlink(UPLOAD_DIR_MODELOS . basename($novoCaminhoImagemParaDB));
            error_log("DEBUG: Nova imagem órfã removida devido a erro de DB: " . UPLOAD_DIR_MODELOS . basename($novoCaminhoImagemParaDB));
        }

        // Trata erro de unicidade (nome de modelo já existente)
        if (isset($e->errorInfo[1]) && $e->errorInfo[1] == 1062) {
            respondeJson('error_client', 'Erro: Já existe outro modelo com este nome.');
        } else {
            respondeJson('error_server', 'Erro de banco de dados ao atualizar o modelo.');
        }
    } catch (Exception $e) {
        error_log("Erro geral ao atualizar modelo {$id_modelo_int}: " . $e->getMessage());
        respondeJson('error_server', 'Ocorreu um erro inesperado ao atualizar o modelo: ' . $e->getMessage());
    } finally {
        fechaConexaoBD($conn); // Fecha a conexão com o banco de dados
    }
}

function inativarModeloPHP($id_modelo) {
    if (empty($id_modelo) || !filter_var($id_modelo, FILTER_VALIDATE_INT)) {
        respondeJson('error_client', "ID do modelo inválido.");
        return;
    }
    $conn = abreConexaoBD();
    try {
        $sql = "UPDATE modelo SET deletado_modelo = 1 WHERE id_modelo = :id_modelo AND deletado_modelo = 0";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':id_modelo', $id_modelo, PDO::PARAM_INT);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            respondeJson('success', 'Modelo inativado com sucesso.');
        } else {
            respondeJson('info', 'Nenhum modelo encontrado com o ID fornecido ou já estava inativado.');
        }
    } catch (PDOException $e) {
        error_log("Erro PDO ao inativar modelo {$id_modelo}: " . $e->getMessage());
        respondeJson('error_server', 'Erro de banco de dados ao inativar o modelo.');
    }
}

function carregarModeloPHP($id_modelo) {
    if (empty($id_modelo) || !filter_var($id_modelo, FILTER_VALIDATE_INT)) {
        respondeJson('error_client', "ID do modelo inválido.");
        return;
    }
    $conn = abreConexaoBD();
    try {
        $sql = "SELECT id_modelo, nome_modelo, cor_modelo, imagem_modelo, descricao_modelo FROM modelo WHERE id_modelo = :id_modelo AND deletado_modelo = 0";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':id_modelo', $id_modelo, PDO::PARAM_INT);
        $stmt->execute();
        $modelo = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($modelo) {
            respondeJson('success', 'Modelo carregado com sucesso.', ['data' => $modelo]);
        } else {
            respondeJson('not_found', 'Modelo não encontrado com o ID fornecido ou estava inativado.');
        }
    } catch (PDOException $e) {
        error_log("Erro PDO ao carregar modelo {$id_modelo}: " . $e->getMessage());
        respondeJson('error_server', 'Erro de banco de dados ao carregar o modelo.');
    }
}

function verificarNomeModeloExistente($nomeModelo) {
    $conn = abreConexaoBD();

    if (empty($nomeModelo)) {
        respondeJson('error', "O nome do modelo não foi fornecido.");
        return;
    }

    $sql = "SELECT COUNT(*) FROM modelo WHERE nome_modelo = :nomeModelo";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':nomeModelo', $nomeModelo);
    $stmt->execute();
    $count = $stmt->fetchColumn();

    echo json_encode(["exists" => ($count > 0)]);
    exit;
}

function verificarNomeModeloExistenteEdicao($nomeModelo, $idModelo) {
    $conn = abreConexaoBD();

    if (empty($nomeModelo) || empty($idModelo)) {
        respondeJson('error', "Nome do modelo ou ID não foram fornecidos para verificação de edição.");
        return;
    }

    $sql = "SELECT COUNT(*)
            FROM modelo
            WHERE nome_modelo = :nomeModelo
            AND id_modelo != :idModelo";

    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':nomeModelo', $nomeModelo);
    $stmt->bindParam(':idModelo', $idModelo, PDO::PARAM_INT);
    $stmt->execute();
    $count = $stmt->fetchColumn();

    echo json_encode(["exists" => ($count > 0)]);
    exit;
}


// ===================== Funções para Marcas
function inserirMarca($nome_marca)
{
    error_log("Função inserirMarca foi chamada com nome: " . $nome_marca);
    if (empty($nome_marca)) {
        respondeJson('error', "O campo 'nome_marca' está vazio.");
    }

    $conn = abreConexaoBD();
    $sql = "INSERT INTO marca (nome_marca) VALUES (:nome_marca)";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':nome_marca', $nome_marca);

    if ($stmt->execute()) {
        respondeJson('success', 'Marca inserida com sucesso!');
    } else {
        respondeJson('error', 'Erro ao inserir a marca.');
    }
}

function listarMarcas($deletado = 0, $searchText = null)
{
    $conn = abreConexaoBD();

    $sql = "SELECT * FROM marca WHERE deletado_marca = :deletado";
    $params = [':deletado' => $deletado];

    if ($searchText !== null && $searchText !== '') {
        $sql .= " AND LOWER(nome_marca) LIKE LOWER(:searchText)";
        $params[':searchText'] = '%' . $searchText . '%';
    }

    $sql .= " ORDER BY nome_marca ASC";

    $stmt = $conn->prepare($sql);

    foreach ($params as $key => &$val) {
        $stmt->bindParam($key, $val);
    }

    $stmt->execute();

    $marcas = $stmt->fetchAll(PDO::FETCH_ASSOC);

    if ($marcas) {
        respondeJson('success', 'Marcas listadas com sucesso.', ['marcas' => $marcas]);
    } else {
        respondeJson('success', 'Nenhuma marca encontrada com os critérios fornecidos.', ['marcas' => []]);
    }
}

function atualizarMarca($id_marca, $nome_marca)
{
    error_log("Função atualizarMarca foi chamada com ID: " . $id_marca . " e nome: " . $nome_marca);
    
    if (empty($id_marca)) {
        respondeJson('error', "O campo 'id_marca' está vazio.");
        return;
    }
    if (empty($nome_marca)) {
        respondeJson('error', "O campo 'nome_marca' está vazio.");
        return;
    }

    $conn = abreConexaoBD();
    $sql = "UPDATE marca SET nome_marca = :nome_marca WHERE id_marca = :id_marca";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':nome_marca', $nome_marca);
    $stmt->bindParam(':id_marca', $id_marca, PDO::PARAM_INT);

    if ($stmt->execute()) {
        respondeJson('success', 'Marca atualizada com sucesso!');
    } else {
        respondeJson('error', 'Erro ao atualizar a marca.');
    }
}

function inativarMarca($id_marca)
{
    if (empty($id_marca)) {
        respondeJson('error', "O campo 'id_marca' está vazio.");
    }

    $conn = abreConexaoBD();
    $sql = "DELETE FROM marca WHERE id_marca = :id_marca"; // Assumindo que 'inativar' significa deletar logicamente
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':id_marca', $id_marca);

    if ($stmt->execute()) {
        respondeJson('success', 'Marca inativada com sucesso!');
    } else {
        respondeJson('error', 'Erro ao inativar a marca.');
    }
}

function carregarMarca($id_marca)
{
    $conn = abreConexaoBD();
    $sql = "SELECT id_marca, nome_marca, deletado_marca FROM marca WHERE id_marca = :id_marca";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':id_marca', $id_marca);
    $stmt->execute();

    $marca = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($marca) {
        respondeJson('success', 'Marca carregada com sucesso.', $marca);
    } else {
        respondeJson('error', 'Nenhuma marca encontrada.');
    }
}

function verificarNomeMarcaExistente($nome_marca)
{
    $conn = abreConexaoBD();
    $sql = "SELECT COUNT(*) FROM marca WHERE nome_marca = :nome_marca";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':nome_marca', $nome_marca);
    $stmt->execute();
    $count = $stmt->fetchColumn();

    if ($count > 0) {
        respondeJson('success', 'Nome da marca já existe.', ['exists' => true]);
    } else {
        respondeJson('success', 'Nome da marca disponível.', ['exists' => false]);
    }
}

function verificarNomeMarcaExistenteEdicao($nome_marca, $id_marca)
{
    error_log("DEBUG PHP: Nome recebido: " . $nome_marca . ", ID recebido: " . $id_marca);

    $conexao = abreConexaoBD();

    if (empty($nome_marca)) {
        respondeJson("error", "O nome da marca não foi fornecido.");
    }

    $sql = "SELECT COUNT(*)
            FROM marca
            WHERE TRIM(nome_marca) = TRIM(:nome_marca)
            AND id_marca != :id_marca";


    $stmt = $conexao->prepare($sql);
    $stmt->bindParam(':nome_marca', $nome_marca);
    $stmt->bindParam(':id_marca', $id_marca, PDO::PARAM_INT);
    $stmt->execute();
    $count = $stmt->fetchColumn();
    error_log("teste: $count" );

    respondeJson("success", "Verificação concluída.", ["exists" => ($count > 0)]);
}



// ===================== Funções para Fornecedores
function inserirFornecedor($nome, $cnpj, $contato, $endereco)
{
    if ( empty($nome) || empty($cnpj) || empty($contato) || empty($endereco)) {
        echo json_encode([
            'status' => 'error',
            'message' => "Alguns campos estão ausentes ou vazios.",
            'data' => [],
        ]);
        exit;
    }

    $conn = abreConexaoBD();
    $sql = "INSERT INTO fornecedor (nome_fornecedor, cnpj_fornecedor, contato_fornecedor, endereco_fornecedor) VALUES (:nome, :cnpj, :contato, :endereco)";

    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':nome', $nome);
    $stmt->bindParam(':cnpj', $cnpj);
    $stmt->bindParam(':contato', $contato);
    $stmt->bindParam(':endereco', $endereco);


    if ($stmt->execute()) {
        echo json_encode(['status' => 'success', 'message' => 'Fornecedor inserido com sucesso!']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Erro ao inserir o fornecedor.']);
    }
}

function atualizarFornecedor($id, $nome, $cnpj, $contato, $endereco, $deletado = 0)
{
    if (empty($id) || empty($nome) || empty($cnpj) || empty($contato) || empty($endereco)) {
        echo json_encode([
            'status' => 'error',
            'message' => "Alguns campos estão ausentes ou vazios.",
            'data' => [],
        ]);
        exit;
    }

    $conn = abreConexaoBD();

    $sql = "UPDATE fornecedor SET nome_fornecedor = :nome, cnpj_fornecedor = :cnpj, contato_fornecedor = :contato, endereco_fornecedor = :endereco" . ($deletado ? ", deletado_fornecedor = :deletado" : "") . " WHERE id_fornecedor = :id";

    $stmt = $conn->prepare($sql);

    $stmt->bindParam(':nome', $nome);
    $stmt->bindParam(':cnpj', $cnpj);
    $stmt->bindParam(':contato', $contato);
    $stmt->bindParam(':endereco', $endereco);
    $stmt->bindParam(':id', $id);

    if ($deletado) {
        $stmt->bindParam(':deletado', $deletado);
    }

    if ($stmt->execute()) {
        echo json_encode(['status' => 'success', 'message' => 'Fornecedor atualizado com sucesso!']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Erro ao atualizar o fornecedor.']);
    }
}

function listarFornecedor($deletado = 0)
{

    $conn = abreConexaoBD();

    $sql = "SELECT * FROM fornecedor WHERE deletado_fornecedor = :deletado";

    $stmt = $conn->prepare($sql);

    $stmt->bindParam(':deletado', $deletado, PDO::PARAM_INT);

    $stmt->execute();

    $fornecedores = $stmt->fetchAll(PDO::FETCH_ASSOC);

    if ($fornecedores) {
        respondeJson('success', 'Fornecedores listados com sucesso.', ['fornecedores' => $fornecedores]);
    } else {
        respondeJson('success', 'Nenhum fornecedor encontrado.', []); // Retorna success com um array vazio
    }
}

function inativarFornecedor($id)
{
    $conn = abreConexaoBD();

    $sql = "UPDATE fornecedor SET deletado_fornecedor = 1 WHERE id_fornecedor = :id";

    $stmt = $conn->prepare($sql);

    $stmt->bindParam(':id', $id);

    if ($stmt->execute()) {
        echo json_encode(['status' => 'success', 'message' => 'Fornecedor deletado com sucesso!']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Erro ao deletar o fornecedor.']);
    }
}

function carregarFornecedor($id)
{
    $conn = abreConexaoBD();
    $sql = "SELECT * FROM fornecedor WHERE id_fornecedor = :id";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':id', $id);
    $stmt->execute();

    $fornecedor = $stmt->fetchAll(PDO::FETCH_ASSOC);

    if ($fornecedor) {
        respondeJson('success', 'Fornecedor carregado com sucesso.', $fornecedor);
    } else {
        respondeJson('error', 'Nenhum fornecedor encontrado.');
    }
}

function verificarCnpjExistente($cnpj)
{
    $conn = abreConexaoBD();

    if (empty($cnpj)) {
        $response = array("status" => "error", "message" => "O CNPJ não foi fornecido.");
        echo json_encode($response);
        return;
    }

    $sql = "SELECT COUNT(*) FROM fornecedor WHERE cnpj_fornecedor = :cnpj";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':cnpj', $cnpj);
    $stmt->execute();
    $count = $stmt->fetchColumn();

    $response = array("exists" => ($count > 0));
    echo json_encode($response);
}

function verificarCnpjExistenteEdicao($cnpj, $idFornecedor)
{

    $conexao = abreConexaoBD();

    if (empty($cnpj)) {
        $response = array("status" => "error", "message" => "O CNPJ não foi fornecido.");
        echo json_encode($response);
        return;
    }

    $sql = "SELECT COUNT(*) 
            FROM fornecedor
            WHERE TRIM(cnpj_fornecedor) = TRIM(:cnpj)
            AND id_fornecedor != :idFornecedor"; 

    $stmt = $conexao->prepare($sql);
    $stmt->bindParam(':cnpj', $cnpj);
    $stmt->bindParam(':idFornecedor', $idFornecedor, PDO::PARAM_INT); 
    $stmt->execute();
    $count = $stmt->fetchColumn();

    $response = array("exists" => ($count > 0));
    echo json_encode($response);
}



// ===================== Funções para Setores
function inserirSetor($tipo, $nome, $responsavel, $descricao, $contato, $email)
{
    if ( empty($tipo) || empty($nome) || empty($responsavel) || empty($descricao) || empty($contato) || empty($email)) {
        echo json_encode([
            'status' => 'error',
            'message' => "Alguns campos estão ausentes ou vazios.",
            'data' => [],
        ]);
        exit;
    }

    $conn = abreConexaoBD();
    $sql = "INSERT INTO setor (tipo_setor, nome_setor, responsavel_setor, descricao_setor, contato_setor, email_setor) 
    VALUES (:tipo, :nome, :responsavel, :descricao, :contato, :email)";

    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':tipo', $tipo);
    $stmt->bindParam(':nome', $nome);
    $stmt->bindParam(':responsavel', $responsavel);
    $stmt->bindParam(':descricao', $descricao);
    $stmt->bindParam(':contato', $contato);
    $stmt->bindParam(':email', $email);


    if ($stmt->execute()) {
        echo json_encode(['status' => 'success', 'message' => 'Setor inserido com sucesso!']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Erro ao inserir o Setor.']);
    }
}

function listarSetor($deletado = 0, $searchText = null, $tipoFiltro = null)
{
    $conn = abreConexaoBD();

    $sql = "SELECT * FROM setor WHERE deletado_setor = :deletado";
    $params = [':deletado' => $deletado];

    if ($searchText !== null && $searchText !== '') {
        $sql .= " AND LOWER(nome_setor) LIKE LOWER(:searchText)";
        $params[':searchText'] = '%' . $searchText . '%';
    }

    if ($tipoFiltro !== null && ($tipoFiltro === 'Interno' || $tipoFiltro === 'Externo')) {
        $sql .= " AND tipo_setor = :tipoFiltro";
        $params[':tipoFiltro'] = $tipoFiltro;
    }

    $stmt = $conn->prepare($sql);

    foreach ($params as $key => &$val) {
        $stmt->bindParam($key, $val);
    }

    $stmt->execute();

    $setores = $stmt->fetchAll(PDO::FETCH_ASSOC);

    if ($setores) {
        respondeJson('success', 'Setores listados com sucesso.', ['setores' => $setores]);
    } else {
        respondeJson('success', 'Nenhum setor encontrado com os critérios fornecidos.', ['setores' => []]);
    }
}

function atualizarSetor($id, $tipo, $nome, $responsavel, $descricao, $contato, $email)
{
    if ( empty($id) || empty($tipo) || empty($nome) || empty($responsavel) || empty($descricao) || empty($contato) || empty($email)) {
        echo json_encode([
            'status' => 'error',
            'message' => "Alguns campos estão ausentes ou vazios.",
            'data' => [],
        ]);
        exit;
    }

    $conn = abreConexaoBD();


    $sql = "UPDATE setor SET
            tipo_setor = :tipo, 
            nome_setor = :nome,
            responsavel_setor = :responsavel, 
            descricao_setor = :descricao,
            contato_setor = :contato,
            email_setor = :email
    WHERE id_setor = :id";

    $stmt = $conn->prepare($sql);

    $stmt->bindParam(':tipo', $tipo);
    $stmt->bindParam(':nome', $nome);
    $stmt->bindParam(':responsavel', $responsavel);
    $stmt->bindParam(':descricao', $descricao);
    $stmt->bindParam(':contato', $contato);
    $stmt->bindParam(':email', $email);
    $stmt->bindParam(':id', $id);


    if ($stmt->execute()) {
        echo json_encode(['status' => 'success', 'message' => 'Setor atualizado com sucesso!']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Erro ao atualizar o Setor.']);
    }
}

function inativarSetor($id)
{
    $conn = abreConexaoBD();

    $sql = "UPDATE setor SET deletado_setor = 1 WHERE id_setor = :id";

    $stmt = $conn->prepare($sql);

    $stmt->bindParam(':id', $id);

    if ($stmt->execute()) {
        echo json_encode(['status' => 'success', 'message' => 'Setor deletado com sucesso!']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Erro ao deletar o Setor.']);
    }
}

function carregarSetor($id)
{
    $conn = abreConexaoBD();
    $sql = "SELECT * FROM setor WHERE id_setor = :id";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':id', $id);
    $stmt->execute();

    $fornecedor = $stmt->fetchAll(PDO::FETCH_ASSOC);

    if ($fornecedor) {
        respondeJson('success', 'Setor carregado com sucesso.', $fornecedor);
    } else {
        respondeJson('error', 'Nenhum setor encontrado.');
    }
}

function verificarSetorExistente($nome)
{
    $conn = abreConexaoBD();

    if (empty($nome)) {
        $response = array("status" => "error", "message" => "O Nome não foi fornecido.");
        echo json_encode($response);
        return;
    }

    $sql = "SELECT COUNT(*) FROM setor WHERE nome_setor = :nome";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':nome', $nome);
    $stmt->execute();
    $count = $stmt->fetchColumn();

    $response = array("exists" => ($count > 0));
    echo json_encode($response);
}

function verificarSetorExistenteEdicao($nome, $id)
{

    $conexao = abreConexaoBD();

    if (empty($nome)) {
        $response = array("status" => "error", "message" => "O Nome não foi fornecido.");
        echo json_encode($response);
        return;
    }

    $sql = "SELECT COUNT(*) 
            FROM setor
            WHERE nome_setor = :nome
            AND id_setor != :id"; 

    $stmt = $conexao->prepare($sql);
    $stmt->bindParam(':nome', $nome);
    $stmt->bindParam(':id', $id, PDO::PARAM_INT); 
    $stmt->execute();
    $count = $stmt->fetchColumn();

    $response = array("exists" => ($count > 0));
    echo json_encode($response);
}

// ===================== Funções para Movimentações

/**
 * Busca patrimônios para seleção na tela de movimentação.
 * Retorna uma lista simplificada de patrimônios.
 */
function buscarPatrimoniosParaSelecaoPHP($termo_busca = null) {
    $conn = abreConexaoBD();
    if ($conn === null) {
        respondeJson('error_server', 'Não foi possível conectar ao banco de dados.');
    }

    try {
        $sql_select = "
            p.id_patrimonio,
            p.codigo_patrimonio,
            p.descricao_patrimonio AS descricao, -- Alias para compatibilidade com PatrimonioParaSelecao
            m.nome_modelo AS marca, -- Usando nome_modelo como marca para simplificar, ajuste se necessário
            m.cor_modelo AS modelo, -- Usando cor_modelo como modelo, ajuste
            p.status_patrimonio AS status,
            p.imagem_patrimonio AS imagem_url, -- Imagem do patrimônio, se houver
            m.imagem_modelo AS imagem_modelo_url, -- Imagem do modelo, como fallback
            s.id_setor AS setor_atual_id,
            s.nome_setor AS setor_atual_nome
        ";
        // Adicionei ALIAS para os campos retornados para facilitar o mapeamento no Dart
        // Se 'marca' e 'modelo' no front se referem à marca e modelo do patrimônio,
        // você já tem id_marca e id_modelo na tabela patrimonio.
        // A query abaixo busca o nome da marca e nome do modelo.

        $sql_from_joins = "
            FROM patrimonio p
            LEFT JOIN modelo m ON p.id_modelo = m.id_modelo
            LEFT JOIN setor s ON p.id_setorAtual = s.id_setor
        ";

        $conditions = ["p.deletado_patrimonio = 0"]; // Apenas patrimônios ativos
        $params = [];

        if (!empty(trim($termo_busca))) {
            $conditions[] = "(p.codigo_patrimonio LIKE :termo OR p.descricao_patrimonio LIKE :termo OR m.nome_modelo LIKE :termo)";
            $params[':termo'] = "%" . trim($termo_busca) . "%";
        }

        $sql_where = " WHERE " . implode(" AND ", $conditions);
        $sql_query = "SELECT " . $sql_select . $sql_from_joins . $sql_where . " ORDER BY p.codigo_patrimonio ASC LIMIT 20"; // Limita os resultados

        $stmt = $conn->prepare($sql_query);
        $stmt->execute($params);
        $raw_patrimonios = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $patrimonios_formatados = [];
        foreach ($raw_patrimonios as $row) {
            $setor_atual_obj = null;
            if ($row['setor_atual_id'] !== null) {
                $setor_atual_obj = [
                    'id' => (int)$row['setor_atual_id'],
                    'nome' => $row['setor_atual_nome']
                ];
            }

            // Prioriza imagem do patrimônio, senão usa a do modelo
            $imagemFinal = $row['imagem_url'] ?? $row['imagem_modelo_url'];

            $patrimonios_formatados[] = [
                'id' => (int)$row['id_patrimonio'],
                'codigo' => $row['codigo_patrimonio'],
                'descricao' => $row['descricao'],
                'marca' => $row['marca'], // Ajuste se o campo 'marca' no frontend espera o nome da marca real
                'modelo' => $row['modelo'], // Ajuste se o campo 'modelo' no frontend espera o nome do modelo real
                'status' => $row['status'],
                'imagem_url' => $imagemFinal,
                'setor_atual' => $setor_atual_obj
            ];
        }

        // O frontend espera um array diretamente sob a chave 'data'
        respondeJson('success', 'Patrimônios encontrados.', $patrimonios_formatados);

    } catch (PDOException $e) {
        error_log("Erro PDO ao buscar patrimônios para seleção: " . $e->getMessage());
        respondeJson('error_server', 'Erro de banco de dados ao buscar patrimônios.');
    } finally {
        fechaConexaoBD($conn);
    }
}


/**
 * Cadastra uma nova movimentação e atualiza o status/setor do patrimônio.
 */
function cadastrarMovimentacaoPHP($id_patrimonio, $id_setor_origem, $id_setor_destino, $data_movimentacao_str, $tipo_movimentacao, $observacao, $id_usuario_responsavel) {
    // Validação básica de entrada
    if (empty($id_patrimonio) || !filter_var($id_patrimonio, FILTER_VALIDATE_INT) ||
        empty($data_movimentacao_str) || empty($tipo_movimentacao) ||
        empty($id_usuario_responsavel) || !filter_var($id_usuario_responsavel, FILTER_VALIDATE_INT)) {
        respondeJson('error_client', 'Campos obrigatórios (Patrimônio, Data, Tipo, Usuário) estão ausentes ou inválidos.');
    }

    // Tipos que exigem setor de destino
    $tipos_requerem_destino = ['ENTRADA', 'TRANSFERENCIA', 'EMPRESTIMO'];
    if (in_array(strtoupper($tipo_movimentacao), $tipos_requerem_destino) && (empty($id_setor_destino) || !filter_var($id_setor_destino, FILTER_VALIDATE_INT))) {
        respondeJson('error_client', 'Setor de destino é obrigatório para este tipo de movimentação.');
    }

    // Tipos que exigem setor de origem (pode vir do patrimônio)
    $tipos_requerem_origem_definida = ['TRANSFERENCIA', 'EMPRESTIMO', 'DESCARTE'];
    if (in_array(strtoupper($tipo_movimentacao), $tipos_requerem_origem_definida) && (empty($id_setor_origem) && $id_setor_origem !== null)) { // Permitir null explicitamente se enviado
         // Se id_setor_origem não foi enviado E não é uma entrada, precisamos buscar do patrimônio.
         // No frontend, o id_setor_origem já é populado com o setor_atual do patrimônio.
         // Se chegar aqui nulo para esses tipos, é um erro de lógica no frontend ou dado faltante.
         // A validação mais robusta da origem (se patrimônio tem setor_atual) já foi feita no controller Dart.
    }


    $conn = abreConexaoBD();
    if ($conn === null) {
        respondeJson('error_server', 'Não foi possível conectar ao banco de dados.');
    }

    try {
        $conn->beginTransaction();

        // 1. Inserir o registro na tabela de movimentação
        $sql_insert_mov = "INSERT INTO movimentacao (id_patrimonio, id_setor_origem, id_setor_destino, data_movimentacao, tipo_movimentacao, observacao, id_usuario_responsavel)
                           VALUES (:id_patrimonio, :id_setor_origem, :id_setor_destino, :data_movimentacao, :tipo_movimentacao, :observacao, :id_usuario_responsavel)";
        $stmt_mov = $conn->prepare($sql_insert_mov);

        $stmt_mov->bindParam(':id_patrimonio', $id_patrimonio, PDO::PARAM_INT);
        $id_origem_param = ($id_setor_origem === null || $id_setor_origem === '') ? null : (int)$id_setor_origem;
        $stmt_mov->bindParam(':id_setor_origem', $id_origem_param, ($id_origem_param === null ? PDO::PARAM_NULL : PDO::PARAM_INT));

        $id_destino_param = ($id_setor_destino === null || $id_setor_destino === '') ? null : (int)$id_setor_destino;
        $stmt_mov->bindParam(':id_setor_destino', $id_destino_param, ($id_destino_param === null ? PDO::PARAM_NULL : PDO::PARAM_INT));

        $stmt_mov->bindParam(':data_movimentacao', $data_movimentacao_str); // Assumindo formato YYYY-MM-DDTHH:MM:SS
        $stmt_mov->bindParam(':tipo_movimentacao', $tipo_movimentacao);
        $obs_param = empty(trim($observacao ?? '')) ? null : trim($observacao);
        $stmt_mov->bindParam(':observacao', $obs_param, ($obs_param === null ? PDO::PARAM_NULL : PDO::PARAM_STR));
        $stmt_mov->bindParam(':id_usuario_responsavel', $id_usuario_responsavel, PDO::PARAM_INT);

        $stmt_mov->execute();
        // $id_nova_movimentacao = $conn->lastInsertId();

        // 2. Atualizar o status e setor_atual do patrimônio
        $novo_status_patrimonio = null;
        $novo_id_setor_atual = null;

        switch (strtoupper($tipo_movimentacao)) {
            case 'ENTRADA':
            case 'TRANSFERENCIA':
            case 'EMPRESTIMO': // Assumindo que empréstimo também significa que está alocado no destino
                $novo_status_patrimonio = 'Alocado';
                $novo_id_setor_atual = $id_setor_destino; // O patrimônio agora está no setor de destino
                break;
            case 'DESCARTE':
                $novo_status_patrimonio = 'Descartado';
                $novo_id_setor_atual = null; // Patrimônio descartado não tem setor atual
                break;
            // Adicione outros casos se necessário (ex: 'EM_MANUTENCAO', 'DEVOLUCAO_EMPRESTIMO')
        }

        if ($novo_status_patrimonio !== null) {
            $sql_update_pat = "UPDATE patrimonio SET status_patrimonio = :status, id_setorAtual = :id_setor_atual WHERE id_patrimonio = :id_patrimonio";
            $stmt_pat = $conn->prepare($sql_update_pat);
            $stmt_pat->bindParam(':status', $novo_status_patrimonio);
            $stmt_pat->bindParam(':id_setor_atual', $novo_id_setor_atual, ($novo_id_setor_atual === null ? PDO::PARAM_NULL : PDO::PARAM_INT));
            $stmt_pat->bindParam(':id_patrimonio', $id_patrimonio, PDO::PARAM_INT);
            $stmt_pat->execute();
        }

        $conn->commit();
        respondeJson('success', 'Movimentação registrada e patrimônio atualizado com sucesso!');

    } catch (PDOException $e) {
        $conn->rollBack();
        error_log("Erro PDO ao cadastrar movimentação: " . $e->getMessage());
        respondeJson('error_server', 'Erro de banco de dados ao registrar movimentação.');
    } finally {
        fechaConexaoBD($conn);
    }
}


function listarMovimentacoesPHP($filtros = []) {
    $conn = abreConexaoBD();
    if ($conn === null) {
        respondeJson('error_server', 'Não foi possível conectar ao banco de dados.');
    }

    try {
        // Definição das colunas a serem selecionadas
        $sql_select = "
            mov.id_movimentacao AS id,
            mov.id_patrimonio AS patrimonio_id,
            p.codigo_patrimonio AS patrimonio_codigo,
            p.descricao_patrimonio AS patrimonio_descricao,
            s.id_setor AS setor_id_movimentacao,
            s.nome_setor AS setor_nome_movimentacao,
            mov.data_hora_mov AS data_movimentacao,
            mov.tipo_movimentacao
            /* -- Colunas que NÃO existem na sua tabela movimentacao ou não podem ser obtidas com a estrutura atual:
            -- observacao (não existe em 'movimentacao')
            -- usuario_nome (não existe 'id_usuario_responsavel' em 'movimentacao' para o JOIN)
            -- origem_setor_id, origem_setor_nome (não existe 'id_setor_origem' em 'movimentacao')
            -- destino_setor_id, destino_setor_nome (vamos usar setor_id_movimentacao como destino implícito)
            */
        "; // A última coluna REAL selecionada é mov.tipo_movimentacao. NÃO coloque vírgula aqui.

        $sql_from_joins = "
            FROM movimentacao mov
            JOIN patrimonio p ON mov.id_patrimonio = p.id_patrimonio
            LEFT JOIN setor s ON mov.id_setor = s.id_setor
        ";

        // ... (resto da lógica de $conditions e $params permanece a mesma) ...
        $conditions = [];
        $params = [];

        if (isset($filtros['patrimonio_query']) && !empty(trim($filtros['patrimonio_query']))) {
            $conditions[] = "(p.codigo_patrimonio LIKE :pat_query OR p.descricao_patrimonio LIKE :pat_query)";
            $params[':pat_query'] = "%" . trim($filtros['patrimonio_query']) . "%";
        }
        if (isset($filtros['data_inicio']) && !empty(trim($filtros['data_inicio']))) {
            $conditions[] = "DATE(mov.data_hora_mov) >= :data_inicio";
            $params[':data_inicio'] = trim($filtros['data_inicio']);
        }
        if (isset($filtros['data_fim']) && !empty(trim($filtros['data_fim']))) {
            $conditions[] = "DATE(mov.data_hora_mov) <= :data_fim";
            $params[':data_fim'] = trim($filtros['data_fim']);
        }
        if (isset($filtros['origem_setor_id']) && filter_var($filtros['origem_setor_id'], FILTER_VALIDATE_INT)) {
            $conditions[] = "mov.id_setor = :filtro_setor_id";
            $params[':filtro_setor_id'] = (int)$filtros['origem_setor_id'];
        } elseif (isset($filtros['destino_setor_id']) && filter_var($filtros['destino_setor_id'], FILTER_VALIDATE_INT)) {
            $conditions[] = "mov.id_setor = :filtro_setor_id";
            $params[':filtro_setor_id'] = (int)$filtros['destino_setor_id'];
        }
        if (isset($filtros['tipo_movimentacao']) && !empty(trim($filtros['tipo_movimentacao']))) {
            $conditions[] = "mov.tipo_movimentacao = :tipo_mov";
            $params[':tipo_mov'] = trim($filtros['tipo_movimentacao']);
        }

        $sql_where = !empty($conditions) ? " WHERE " . implode(" AND ", $conditions) : "";
        
        // Garante um espaço entre a última coluna selecionada e o FROM
        $sql_query = "SELECT " . trim($sql_select) . " " . trim($sql_from_joins) . " " . trim($sql_where) . " ORDER BY mov.data_hora_mov DESC, mov.id_movimentacao DESC LIMIT 100";

        error_log("SQL Query Gerada (listarMovimentacoesPHP): " . $sql_query);
        error_log("Parâmetros para a Query (listarMovimentacoesPHP): " . print_r($params, true));

        $stmt = $conn->prepare($sql_query);
        $stmt->execute($params);
        $raw_movimentacoes = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $movimentacoes_formatadas = [];
        foreach ($raw_movimentacoes as $row) {
            $setor_da_movimentacao = null;
            if (isset($row['setor_id_movimentacao']) && $row['setor_id_movimentacao'] !== null) {
                $setor_da_movimentacao = ['id' => (int)$row['setor_id_movimentacao'], 'nome' => $row['setor_nome_movimentacao']];
            }

            $origem_setor_para_dart = null;
            $destino_setor_para_dart = null;
            $tipo_upper = strtoupper($row['tipo_movimentacao']);

            if ($tipo_upper === 'ENTRADA' || $tipo_upper === 'TRANSFERENCIA' || $tipo_upper === 'EMPRESTIMO') {
                $destino_setor_para_dart = $setor_da_movimentacao;
            } elseif ($tipo_upper === 'DESCARTE') {
                $origem_setor_para_dart = $setor_da_movimentacao;
            } else {
                 $destino_setor_para_dart = $setor_da_movimentacao;
            }

            $movimentacoes_formatadas[] = [
                'id' => (int)$row['id'],
                'patrimonio_id' => (int)$row['patrimonio_id'],
                'patrimonio_codigo' => $row['patrimonio_codigo'],
                'patrimonio_descricao' => $row['patrimonio_descricao'],
                'origem_setor' => $origem_setor_para_dart,
                'destino_setor' => $destino_setor_para_dart,
                'data_movimentacao' => $row['data_movimentacao'],
                'tipo_movimentacao' => $row['tipo_movimentacao'],
                'observacao' => null,
                'usuario_nome' => 'N/A'
            ];
        }
        
        respondeJson('success', 'Movimentações listadas com sucesso.', $movimentacoes_formatadas);

    } catch (PDOException $e) {
        error_log("Erro PDO ao listar movimentações: " . $e->getMessage());
        respondeJson('error_server', 'Erro de banco de dados ao listar movimentações: ' . $e->getMessage());
    } finally {
        $conn = null;
    }
}

// ===================== Funções para Patrimonios
define('UPLOAD_DIR_PATRIMONIO', 'C:\xampp\htdocs\api\imagens_patrimonio\\'); 
define('UPLOAD_URL_PATRIMONIO', 'http://192.168.100.47/api/imagens_patrimonio/');

function inserirPatrimonioPHP($codigo_patrimonio, $tipo_patrimonio, $descricao_patrimonio, $setor_origem_id, $nfe_patrimonio, $lote_patrimonio, $dataentrada_patrimonio, $id_modelo, $id_marca, $id_fornecedor)
{
    error_log("inserirPatrimonioPHP chamado para código: $codigo_patrimonio");

    if (empty(trim($codigo_patrimonio)) || empty(trim($tipo_patrimonio)) || empty($setor_origem_id) || empty($id_modelo) || empty($id_marca) || empty($id_fornecedor)) {
        respondeJson('error_client', "Campos obrigatórios (Código, Tipo, Setor de Origem, Modelo, Marca, Fornecedor) estão ausentes.");
        return;
    }

    $conn = abreConexaoBD();
    $imagem_patrimonio_url = null;


    if (isset($_FILES['imagem_patrimonio']) && $_FILES['imagem_patrimonio']['error'] === UPLOAD_ERR_OK) {
        $arquivoTemp = $_FILES['imagem_patrimonio']['tmp_name'];
        $nomeOriginal = $_FILES['imagem_patrimonio']['name'];
        $extensao = pathinfo($nomeOriginal, PATHINFO_EXTENSION);
        $nomeArquivoUnico = uniqid('patrimonio_') . '.' . $extensao;
        $caminhoDestinoCompleto = UPLOAD_DIR_PATRIMONIO . $nomeArquivoUnico;
        $imagem_patrimonio_url = UPLOAD_URL_PATRIMONIO . $nomeArquivoUnico; // URL para o DB

        if (!is_dir(UPLOAD_DIR_PATRIMONIO)) {
            if (!mkdir(UPLOAD_DIR_PATRIMONIO, 0755, true)) {
                respondeJson('error_server', 'Falha ao criar diretório de upload para imagens de patrimônio.');
                return;
            }
        }

        if (!move_uploaded_file($arquivoTemp, $caminhoDestinoCompleto)) {
            $erro = error_get_last();
            error_log("ERRO ao mover o arquivo para $caminhoDestinoCompleto. Erro PHP: " . print_r($erro, true));
            respondeJson('error_server', 'Falha ao mover a imagem para o servidor.');
            return;
        }
        error_log("Imagem de patrimônio salva com sucesso: $imagem_patrimonio_url");
    } else {
        error_log("Nenhuma imagem de patrimônio enviada. Buscando imagem do modelo #$id_modelo...");
        try {
            $stmt_modelo = $conn->prepare("SELECT imagem_modelo FROM modelo WHERE id_modelo = :id_modelo AND deletado_modelo = 0");
            $stmt_modelo->bindParam(':id_modelo', $id_modelo, PDO::PARAM_INT);
            $stmt_modelo->execute();
            $result_modelo = $stmt_modelo->fetch(PDO::FETCH_ASSOC);

            if ($result_modelo && $result_modelo['imagem_modelo']) {
                $imagem_patrimonio_url = $result_modelo['imagem_modelo'];
                error_log("Imagem do modelo encontrada e usada: $imagem_patrimonio_url");
            } else {
                error_log("Modelo não encontrado ou não possui imagem. Usando imagem padrão ou null.");
            }
        } catch (PDOException $e) {
            error_log("Erro PDO ao buscar imagem do modelo: " . $e->getMessage());
            respondeJson('error_server', 'Erro de banco de dados ao buscar imagem do modelo.');
            return;
        }
    }

    // Definir campos padrão
    $status_patrimonio = 'Alocado';
    $deletado_patrimonio = 0;
    $id_setorAtual = $setor_origem_id;


    try {
        $sql = "INSERT INTO patrimonio (codigo_patrimonio, imagem_patrimonio, tipo_patrimonio, descricao_patrimonio, status_patrimonio, deletado_patrimonio, setor_origem_id, nfe_patrimonio, lote_patrimonio, dataentrada_patrimonio, id_modelo, id_marca, id_fornecedor, id_setorAtual)
                VALUES (:codigo_patrimonio, :imagem_patrimonio, :tipo_patrimonio, :descricao_patrimonio, :status_patrimonio, :deletado_patrimonio, :setor_origem_id, :nfe_patrimonio, :lote_patrimonio, :dataentrada_patrimonio, :id_modelo, :id_marca, :id_fornecedor, :id_setorAtual)";
        
        $stmt = $conn->prepare($sql);

        // Binding dos parâmetros
        $stmt->bindParam(':codigo_patrimonio', $codigo_patrimonio);
        $stmt->bindParam(':imagem_patrimonio', $imagem_patrimonio_url, ($imagem_patrimonio_url === null ? PDO::PARAM_NULL : PDO::PARAM_STR));
        $stmt->bindParam(':tipo_patrimonio', $tipo_patrimonio);
        $desc = empty(trim($descricao_patrimonio ?? '')) ? null : $descricao_patrimonio;
        $stmt->bindParam(':descricao_patrimonio', $desc, ($desc === null ? PDO::PARAM_NULL : PDO::PARAM_STR));
        $stmt->bindParam(':status_patrimonio', $status_patrimonio);
        $stmt->bindParam(':deletado_patrimonio', $deletado_patrimonio, PDO::PARAM_INT);
        $stmt->bindParam(':setor_origem_id', $setor_origem_id, PDO::PARAM_INT);
        $nfe = empty(trim($nfe_patrimonio ?? '')) ? null : $nfe_patrimonio;
        $stmt->bindParam(':nfe_patrimonio', $nfe, ($nfe === null ? PDO::PARAM_NULL : PDO::PARAM_STR));
        $lote = empty(trim($lote_patrimonio ?? '')) ? null : $lote_patrimonio;
        $stmt->bindParam(':lote_patrimonio', $lote, ($lote === null ? PDO::PARAM_NULL : PDO::PARAM_STR));
        $data_aq = empty(trim($dataentrada_patrimonio ?? '')) ? null : $dataentrada_patrimonio;
        $stmt->bindParam(':dataentrada_patrimonio', $data_aq, ($data_aq === null ? PDO::PARAM_NULL : PDO::PARAM_STR));
        $stmt->bindParam(':id_modelo', $id_modelo, PDO::PARAM_INT);
        $stmt->bindParam(':id_marca', $id_marca, PDO::PARAM_INT);
        $stmt->bindParam(':id_fornecedor', $id_fornecedor, PDO::PARAM_INT);
        $stmt->bindParam(':id_setorAtual', $id_setorAtual, PDO::PARAM_INT);

        $stmt->execute();
        $lastId = $conn->lastInsertId();
        
        respondeJson('created', 'Patrimônio inserido com sucesso.', ['id_patrimonio' => $lastId, 'imagem_url' => $imagem_patrimonio_url]);

    } catch (PDOException $e) {
        error_log("Erro PDO inserirPatrimonio: " . $e->getMessage());
        if ($imagem_patrimonio_url && isset($_FILES['imagem_patrimonio']) && file_exists(UPLOAD_DIR_PATRIMONIO . basename($imagem_patrimonio_url))) {
            unlink(UPLOAD_DIR_PATRIMONIO . basename($imagem_patrimonio_url));
            error_log("DEBUG: Nova imagem órfã de patrimônio removida devido a erro de DB.");
        }
        if (isset($e->errorInfo[1]) && $e->errorInfo[1] == 1062) {
            respondeJson('error_client', 'Erro: Já existe um patrimônio com este código.');
        } else {
            respondeJson('error_server', 'Erro de banco de dados ao inserir o patrimônio.');
        }
    } finally {
        fechaConexaoBD($conn);
    }
}

function listarPatrimoniosPHP($page = 1, $limit = 10, $deletado = 0, $filtros = [])
{
    $conn = abreConexaoBD();

    $page = filter_var($page, FILTER_VALIDATE_INT, ['options' => ['default' => 1, 'min_range' => 1]]);
    $limit = filter_var($limit, FILTER_VALIDATE_INT, ['options' => ['default' => 10, 'min_range' => 1]]);
    $deletado = filter_var($deletado, FILTER_VALIDATE_INT, ['options' => ['default' => 0, 'min_range' => 0, 'max_range' => 1]]);
    $offset = ($page - 1) * $limit;

    try {
        $sql_select_columns = "
            p.id_patrimonio,
            p.codigo_patrimonio,
            p.imagem_patrimonio,
            p.tipo_patrimonio,
            p.descricao_patrimonio,
            
            p.deletado_patrimonio,
            p.setor_origem_id,
            p.nfe_patrimonio,
            p.lote_patrimonio,
            p.dataentrada_patrimonio,
            p.id_modelo,
            p.id_marca,
            p.id_fornecedor,
            p.id_setorAtual,
            -- Dados do Modelo (para aninhamento no JSON)
            m.id_modelo AS modelo_id,
            m.nome_modelo,
            m.cor_modelo,
            m.imagem_modelo AS modelo_imagem,
            m.descricao_modelo AS modelo_descricao,
            m.deletado_modelo AS modelo_deletado,
            -- Dados da Marca (para aninhamento no JSON)
            ma.id_marca AS marca_id,
            ma.nome_marca,
            ma.deletado_marca AS marca_deletado,
            -- Dados do Fornecedor (para aninhamento no JSON)
            f.id_fornecedor AS fornecedor_id,
            f.nome_fornecedor,
            f.cnpj_fornecedor,
            f.contato_fornecedor,
            f.endereco_fornecedor,
            f.deletado_fornecedor,
            -- Dados do Setor de Origem (para aninhamento no JSON)
            so.id_setor AS setor_origem_id_obj,
            so.nome_setor AS nome_setor_origem,
            so.descricao_setor AS descricao_setor_origem,
            so.deletado_setor AS deletado_setor_origem,
            -- Dados do Setor Atual (para aninhamento no JSON)
            sa.id_setor AS setor_atual_id_obj,
            sa.nome_setor AS nome_setor_atual,
            sa.descricao_setor AS descricao_setor_atual,
            sa.deletado_setor AS deletado_setor_atual
        ";

        $sql_from_joins = "
            FROM patrimonio p
            LEFT JOIN modelo m ON p.id_modelo = m.id_modelo
            LEFT JOIN marca ma ON p.id_marca = ma.id_marca
            LEFT JOIN fornecedor f ON p.id_fornecedor = f.id_fornecedor
            LEFT JOIN setor so ON p.setor_origem_id = so.id_setor
            LEFT JOIN setor sa ON p.id_setorAtual = sa.id_setor
        ";

        $conditions = ["p.deletado_patrimonio = :deletado"];
        $params = [':deletado' => $deletado];

        // Adicionar filtros dinâmicos
        if (isset($filtros['codigo_patrimonio']) && !empty(trim($filtros['codigo_patrimonio']))) {
            $conditions[] = "p.codigo_patrimonio LIKE :codigo_patrimonio";
            $params[':codigo_patrimonio'] = "%" . trim($filtros['codigo_patrimonio']) . "%";
        }
        if (isset($filtros['tipo_patrimonio']) && !empty(trim($filtros['tipo_patrimonio']))) {
            $conditions[] = "p.tipo_patrimonio = :tipo_patrimonio";
            $params[':tipo_patrimonio'] = trim($filtros['tipo_patrimonio']);
        }
        if (isset($filtros['id_modelo']) && !empty($filtros['id_modelo'])) {
            $conditions[] = "p.id_modelo = :id_modelo";
            $params[':id_modelo'] = filter_var($filtros['id_modelo'], FILTER_VALIDATE_INT);
        }
        if (isset($filtros['id_marca']) && !empty($filtros['id_marca'])) {
            $conditions[] = "p.id_marca = :id_marca";
            $params[':id_marca'] = filter_var($filtros['id_marca'], FILTER_VALIDATE_INT);
        }
        if (isset($filtros['id_fornecedor']) && !empty($filtros['id_fornecedor'])) {
            $conditions[] = "p.id_fornecedor = :id_fornecedor";
            $params[':id_fornecedor'] = filter_var($filtros['id_fornecedor'], FILTER_VALIDATE_INT);
        }
        if (isset($filtros['id_setorAtual']) && !empty($filtros['id_setorAtual'])) {
            $conditions[] = "p.id_setorAtual = :id_setorAtual";
            $params[':id_setorAtual'] = filter_var($filtros['id_setorAtual'], FILTER_VALIDATE_INT);
        }
        // ... adicione mais filtros conforme necessário

        $sql_where = !empty($conditions) ? " WHERE " . implode(" AND ", $conditions) : "";

        // Query para obter os dados dos patrimônios
        $sql_data = "SELECT " . $sql_select_columns . $sql_from_joins . $sql_where . " ORDER BY p.codigo_patrimonio ASC LIMIT :limit OFFSET :offset";
        $stmt_data = $conn->prepare($sql_data);

        // Bind dos parâmetros para a query de dados
        foreach ($params as $key => &$val) {
            $type = PDO::PARAM_STR;
            if (strpos($key, 'id_') !== false || $key === ':deletado' || strpos($key, '_id') !== false) { // Detecta IDs e deletado como INT
                $type = PDO::PARAM_INT;
            }
            $stmt_data->bindParam($key, $val, $type);
        }
        unset($val); // Quebra a referência para evitar problemas em loops subsequentes

        $stmt_data->bindParam(':limit', $limit, PDO::PARAM_INT);
        $stmt_data->bindParam(':offset', $offset, PDO::PARAM_INT);
        $stmt_data->execute();
        
        $raw_patrimonios = $stmt_data->fetchAll(PDO::FETCH_ASSOC);

        // Formatando os resultados para aninhar os objetos relacionados
        $patrimonios = [];
        foreach ($raw_patrimonios as $row) {

            $modelo = null;
            if ($row['modelo_id'] !== null) { // Apenas cria o objeto modelo se houver dados
                $modelo = [
                    'id_modelo' => (int)$row['modelo_id'],
                    'nome_modelo' => $row['nome_modelo'],
                    'cor_modelo' => $row['cor_modelo'],
                    'imagem_modelo' => $row['modelo_imagem'],
                    'descricao_modelo' => $row['modelo_descricao'],
                    'deletado_modelo' => (int)$row['modelo_deletado']
                ];
            }

            $marca = null;
            if ($row['marca_id'] !== null) { // Apenas cria o objeto marca se houver dados
                $marca = [
                    'id_marca' => (int)$row['marca_id'],
                    'nome_marca' => $row['nome_marca'],
                    'deletado_marca' => (int)$row['marca_deletado']
                ];
            }

            $fornecedor = null;
            if ($row['fornecedor_id'] !== null) { // Apenas cria o objeto fornecedor se houver dados
                $fornecedor = [
                    'id_fornecedor' => (int)$row['fornecedor_id'],
                    'nome_fornecedor' => $row['nome_fornecedor'],
                    'cnpj_fornecedor' => $row['cnpj_fornecedor'],
                    'contato_fornecedor' => $row['contato_fornecedor'],
                    'endereco_fornecedor' => $row['endereco_fornecedor'],
                    'deletado_fornecedor' => (int)$row['deletado_fornecedor']
                ];
            }

            $setor_origem = null;
            if ($row['setor_origem_id_obj'] !== null) { // Apenas cria o objeto setor se houver dados
                $setor_origem = [
                    'id_setor' => (int)$row['setor_origem_id_obj'],
                    'nome_setor' => $row['nome_setor_origem'],
                    'descricao_setor' => $row['descricao_setor_origem'],
                    'deletado_setor' => (int)$row['deletado_setor_origem']
                ];
            }

            $setor_atual = null;
            if ($row['setor_atual_id_obj'] !== null) { // Apenas cria o objeto setor se houver dados
                $setor_atual = [
                    'id_setor' => (int)$row['setor_atual_id_obj'],
                    'nome_setor' => $row['nome_setor_atual'],
                    'descricao_setor' => $row['descricao_setor_atual'],
                    'deletado_setor' => (int)$row['deletado_setor_atual']
                ];
            }

            $patrimonio = [
                'id_patrimonio' => (int)$row['id_patrimonio'],
                'codigo_patrimonio' => $row['codigo_patrimonio'],
                'imagem_patrimonio' => $row['imagem_patrimonio'],
                'tipo_patrimonio' => $row['tipo_patrimonio'],
                'descricao_patrimonio' => $row['descricao_patrimonio'],
                'status_patrimonio' => $row['status_patrimonio'],
                'deletado_patrimonio' => (int)$row['deletado_patrimonio'],
                'nfe_patrimonio' => $row['nfe_patrimonio'],
                'lote_patrimonio' => $row['lote_patrimonio'],
                'dataentrada_patrimonio' => $row['dataentrada_patrimonio'],
                'modelo' => $modelo, // Objeto modelo aninhado
                'marca' => $marca,   // Objeto marca aninhado
                'fornecedor' => $fornecedor, // Objeto fornecedor aninhado
                'setor_origem' => $setor_origem, // Objeto setor de origem aninhado
                'setor_atual' => $setor_atual   // Objeto setor atual aninhado
            ];
            $patrimonios[] = $patrimonio;
        }

        // Query para contar o total de registros (para paginação)
        $sql_count = "SELECT COUNT(*) " . $sql_from_joins . $sql_where;
        $stmt_count = $conn->prepare($sql_count);
        // Bind dos parâmetros para a query de contagem (reutiliza os mesmos filtros)
        foreach ($params as $key => &$val) {
            $type = PDO::PARAM_STR;
            if (strpos($key, 'id_') !== false || $key === ':deletado' || strpos($key, '_id') !== false) {
                $type = PDO::PARAM_INT;
            }
            $stmt_count->bindParam($key, $val, $type);
        }
        unset($val);
        $stmt_count->execute();
        $total_records = (int)$stmt_count->fetchColumn();

        // AQUI ESTÁ A MUDANÇA PRINCIPAL:
        // A chave 'data' no objeto principal agora contém a lista de patrimônios diretamente.
        // As chaves 'total', 'page', 'limit' estão no mesmo nível.
        respondeJson('success', 'Patrimônios listados.', [
            'data' => $patrimonios, // Esta é a lista de patrimônios
            'total' => $total_records,
            'page' => $page,
            'limit' => $limit
        ]);

    } catch (PDOException $e) {
        error_log("Erro PDO listarPatrimonios: " . $e->getMessage());
        respondeJson('error_server', 'Erro ao listar patrimônios.');
    } finally {
        fechaConexaoBD($conn);
    }
}

function carregarPatrimonioPHP($id_patrimonio)
{
    error_log("carregarPatrimonioPHP chamado para ID: $id_patrimonio");

    if (empty($id_patrimonio) || !filter_var($id_patrimonio, FILTER_VALIDATE_INT)) {
        respondeJson('error_client', "ID do patrimônio inválido.");
        return;
    }

    $conn = abreConexaoBD();

    try {
        $sql = "SELECT
            p.id_patrimonio,
            p.codigo_patrimonio,
            p.imagem_patrimonio,
            p.tipo_patrimonio,
            p.descricao_patrimonio,
            p.status_patrimonio,
            p.deletado_patrimonio,
            p.setor_origem_id,
            p.nfe_patrimonio,
            p.lote_patrimonio,
            p.dataentrada_patrimonio,
            p.id_modelo,
            p.id_marca,
            p.id_fornecedor,
            p.id_setorAtual,
            -- Dados do Modelo
            m.id_modelo AS modelo_id,
            m.nome_modelo,
            m.cor_modelo,
            m.imagem_modelo AS modelo_imagem,
            m.descricao_modelo AS modelo_descricao,
            m.deletado_modelo AS modelo_deletado,
            -- Dados da Marca
            ma.id_marca AS marca_id,
            ma.nome_marca,
            ma.deletado_marca AS marca_deletado,
            -- Dados do Fornecedor
            f.id_fornecedor AS fornecedor_id,
            f.nome_fornecedor,
            f.cnpj_fornecedor,
            f.contato_fornecedor,
            f.endereco_fornecedor,
            f.deletado_fornecedor,
            -- Dados do Setor de Origem
            so.id_setor AS setor_origem_id_obj,
            so.nome_setor AS nome_setor_origem,
            so.descricao_setor AS descricao_setor_origem,
            so.deletado_setor AS deletado_setor_origem,
            -- Dados do Setor Atual
            sa.id_setor AS setor_atual_id_obj,
            sa.nome_setor AS nome_setor_atual,
            sa.descricao_setor AS descricao_setor_atual,
            sa.deletado_setor AS deletado_setor_atual
        FROM
            patrimonio p
        LEFT JOIN modelo m ON p.id_modelo = m.id_modelo
        LEFT JOIN marca ma ON p.id_marca = ma.id_marca
        LEFT JOIN fornecedor f ON p.id_fornecedor = f.id_fornecedor
        LEFT JOIN setor so ON p.setor_origem_id = so.id_setor
        LEFT JOIN setor sa ON p.id_setorAtual = sa.id_setor
        WHERE
            p.id_patrimonio = :id_patrimonio AND p.deletado_patrimonio = 0";
        
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':id_patrimonio', $id_patrimonio, PDO::PARAM_INT);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($row) {
            // Formatar o resultado para aninhar os objetos
            $patrimonio_data = [
                'id_patrimonio' => (int)$row['id_patrimonio'],
                'codigo_patrimonio' => $row['codigo_patrimonio'],
                'imagem_patrimonio' => $row['imagem_patrimonio'],
                'tipo_patrimonio' => $row['tipo_patrimonio'],
                'descricao_patrimonio' => $row['descricao_patrimonio'],
                'status_patrimonio' => $row['status_patrimonio'],
                'deletado_patrimonio' => (int)$row['deletado_patrimonio'],
                'setor_origem_id' => (int)$row['setor_origem_id'],
                'nfe_patrimonio' => $row['nfe_patrimonio'],
                'lote_patrimonio' => $row['lote_patrimonio'],
                'dataentrada_patrimonio' => $row['dataentrada_patrimonio'],
                'id_modelo' => (int)$row['id_modelo'],
                'id_marca' => (int)$row['id_marca'],
                'id_fornecedor' => (int)$row['id_fornecedor'],
                'id_setorAtual' => (int)$row['id_setorAtual'],
                'modelo' => [
                    'id_modelo' => (int)$row['modelo_id'],
                    'nome_modelo' => $row['nome_modelo'],
                    'cor_modelo' => $row['cor_modelo'],
                    'imagem_modelo' => $row['modelo_imagem'],
                    'descricao_modelo' => $row['modelo_descricao'],
                    'deletado_modelo' => (int)$row['modelo_deletado']
                ],
                'marca' => [
                    'id_marca' => (int)$row['marca_id'],
                    'nome_marca' => $row['nome_marca'],
                    'deletado_marca' => (int)$row['marca_deletado']
                ],
                'fornecedor' => [
                    'id_fornecedor' => (int)$row['fornecedor_id'],
                    'nome_fornecedor' => $row['nome_fornecedor'],
                    'cnpj_fornecedor' => $row['cnpj_fornecedor'],
                    'contato_fornecedor' => $row['contato_fornecedor'],
                    'endereco_fornecedor' => $row['endereco_fornecedor'],
                    'deletado_fornecedor' => (int)$row['deletado_fornecedor']
                ],
                'setor_origem' => [
                    'id_setor' => (int)$row['setor_origem_id_obj'],
                    'nome_setor' => $row['nome_setor_origem'],
                    'descricao_setor' => $row['descricao_setor_origem'],
                    'deletado_setor' => (int)$row['deletado_setor_origem']
                ],
                'setor_atual' => [
                    'id_setor' => (int)$row['setor_atual_id_obj'],
                    'nome_setor' => $row['nome_setor_atual'],
                    'descricao_setor' => $row['descricao_setor_atual'],
                    'deletado_setor' => (int)$row['deletado_setor_atual']
                ]
            ];
            respondeJson('success', 'Patrimônio carregado com sucesso.', ['data' => $patrimonio_data]);
        } else {
            respondeJson('not_found', 'Patrimônio não encontrado com o ID fornecido ou estava inativado.');
        }
    } catch (PDOException $e) {
        error_log("Erro PDO carregarPatrimonio: " . $e->getMessage());
        respondeJson('error_server', 'Erro de banco de dados ao carregar o patrimônio.');
    } finally {
        fechaConexaoBD($conn);
    }
}

function atualizarPatrimonioPHP($id_patrimonio, $codigo_patrimonio, $tipo_patrimonio, $descricao_patrimonio, $setor_origem_id, $nfe_patrimonio, $lote_patrimonio, $dataentrada_patrimonio, $id_modelo, $id_marca, $id_fornecedor, $id_setorAtual)
{
    error_log("atualizarPatrimonioPHP chamado para ID: $id_patrimonio");

    $id_patrimonio_int = filter_var($id_patrimonio, FILTER_VALIDATE_INT);
    if ($id_patrimonio_int === false || $id_patrimonio_int <= 0) {
        respondeJson('error_client', "ID do patrimônio inválido.");
        return;
    }
    // Validação de campos obrigatórios para atualização
    if (empty(trim($codigo_patrimonio)) || empty(trim($tipo_patrimonio)) || empty($setor_origem_id) || empty($id_modelo) || empty($id_marca) || empty($id_fornecedor) || empty($id_setorAtual)) {
        respondeJson('error_client', "Campos obrigatórios (Código, Tipo, Setor de Origem, Modelo, Marca, Fornecedor, Setor Atual) estão ausentes.");
        return;
    }

    $conn = abreConexaoBD();

    $caminhoImagemAntigaNoDB = null;     // URL da imagem atual no DB
    $novoCaminhoImagemParaDB = null;     // Nova URL da imagem para o DB (se houver alteração)
    $shouldUpdateImageColumn = false;    // Indica se a coluna 'imagem_patrimonio' deve ser atualizada

    try {
        // 1. Obter os dados atuais do patrimônio, incluindo o caminho da imagem
        $stmt_current_data = $conn->prepare("SELECT codigo_patrimonio, imagem_patrimonio, id_modelo FROM patrimonio WHERE id_patrimonio = :id_patrimonio AND deletado_patrimonio = 0");
        $stmt_current_data->bindParam(':id_patrimonio', $id_patrimonio_int, PDO::PARAM_INT);
        $stmt_current_data->execute();
        $patrimonioExistente = $stmt_current_data->fetch(PDO::FETCH_ASSOC);

        if (!$patrimonioExistente) {
            respondeJson('not_found', 'Patrimônio não encontrado ou inativado.');
            return;
        }
        $caminhoImagemAntigaNoDB = $patrimonioExistente['imagem_patrimonio']; // Pode ser NULL
        $modeloIdAntigo = $patrimonioExistente['id_modelo'];

        // Flag para verificar se houveram mudanças nos dados textuais
        $dataChanged = false;
        // Compare todos os campos exceto id_patrimonio e imagem_patrimonio
        // Você precisará comparar $patrimonioExistente com os parâmetros recebidos.
        // Simplificado aqui, mas em um cenário real, você compararia cada campo.
        if ($patrimonioExistente['codigo_patrimonio'] !== $codigo_patrimonio ||
            $patrimonioExistente['tipo_patrimonio'] !== $tipo_patrimonio ||
            (trim($patrimonioExistente['descricao_patrimonio'] ?? '') !== trim($descricao_patrimonio ?? '')) ||
            (int)$patrimonioExistente['setor_origem_id'] !== (int)$setor_origem_id ||
            (trim($patrimonioExistente['nfe_patrimonio'] ?? '') !== trim($nfe_patrimonio ?? '')) ||
            (trim($patrimonioExistente['lote_patrimonio'] ?? '') !== trim($lote_patrimonio ?? '')) ||
            (trim($patrimonioExistente['dataentrada_patrimonio'] ?? '') !== trim($dataentrada_patrimonio ?? '')) ||
            (int)$patrimonioExistente['id_modelo'] !== (int)$id_modelo ||
            (int)$patrimonioExistente['id_marca'] !== (int)$id_marca ||
            (int)$patrimonioExistente['id_fornecedor'] !== (int)$id_fornecedor ||
            (int)$patrimonioExistente['id_setorAtual'] !== (int)$id_setorAtual
            ) {
            $dataChanged = true;
        }

        // 2. Lógica de tratamento da IMAGEM
        // 2a. Se uma NOVA imagem foi enviada via upload do Flutter
        if (isset($_FILES['imagem_patrimonio']) && $_FILES['imagem_patrimonio']['error'] === UPLOAD_ERR_OK) {
            $arquivoTemp = $_FILES['imagem_patrimonio']['tmp_name'];
            $nomeOriginal = $_FILES['imagem_patrimonio']['name'];
            $extensao = pathinfo($nomeOriginal, PATHINFO_EXTENSION);
            $nomeArquivoUnico = uniqid('patrimonio_') . '.' . $extensao;
            $caminhoDestinoCompletoNoServidor = UPLOAD_DIR_PATRIMONIO . $nomeArquivoUnico;
            $novoCaminhoImagemParaDB = UPLOAD_URL_PATRIMONIO . $nomeArquivoUnico; // URL para o DB

            if (!is_dir(UPLOAD_DIR_PATRIMONIO)) {
                if (!mkdir(UPLOAD_DIR_PATRIMONIO, 0755, true)) {
                    respondeJson('error_server', 'Falha ao criar diretório de upload para imagens de patrimônio.');
                    return;
                }
            }

            if (!move_uploaded_file($arquivoTemp, $caminhoDestinoCompletoNoServidor)) {
                $erro = error_get_last();
                error_log("ERRO ao mover o arquivo na atualização para $caminhoDestinoCompletoNoServidor. Erro PHP: " . print_r($erro, true));
                respondeJson('error_server', 'Falha ao mover a nova imagem para o servidor.');
                return;
            }
            $shouldUpdateImageColumn = true;

            // Excluir a imagem antiga do servidor, SE ela não for a imagem original do modelo e não for a imagem padrão
            // E se a imagem antiga realmente existe no nosso diretório de upload de patrimônios
            if ($caminhoImagemAntigaNoDB &&
                strpos($caminhoImagemAntigaNoDB, UPLOAD_URL_PATRIMONIO) === 0 && // Verifica se é uma imagem de patrimônio customizada
                (basename($caminhoImagemAntigaNoDB) !== 'default_patrimonio.png') && // Ajuste se tiver imagem padrão
                file_exists(UPLOAD_DIR_PATRIMONIO . basename($caminhoImagemAntigaNoDB))) {
                
                unlink(UPLOAD_DIR_PATRIMONIO . basename($caminhoImagemAntigaNoDB));
                error_log("DEBUG: Imagem antiga de patrimônio removida (substituída): " . UPLOAD_DIR_PATRIMONIO . basename($caminhoImagemAntigaNoDB));
            }

        } elseif ((int)$id_modelo !== (int)$modeloIdAntigo) {
            // 2b. Se o ID do Modelo MUDOU e NENHUMA imagem foi enviada (significa que quer usar a imagem do NOVO modelo)
            error_log("ID do modelo mudou, buscando imagem do novo modelo #$id_modelo...");
            $stmt_novo_modelo_img = $conn->prepare("SELECT imagem_modelo FROM modelo WHERE id_modelo = :id_modelo AND deletado_modelo = 0");
            $stmt_novo_modelo_img->bindParam(':id_modelo', $id_modelo, PDO::PARAM_INT);
            $stmt_novo_modelo_img->execute();
            $result_novo_modelo_img = $stmt_novo_modelo_img->fetch(PDO::FETCH_ASSOC);

            $novoCaminhoImagemParaDB = $result_novo_modelo_img ? $result_novo_modelo_img['imagem_modelo'] : null;
            $shouldUpdateImageColumn = true; // Sinaliza que a imagem no DB precisa ser atualizada

            // Opcional: Se a imagem antiga era uma imagem CUSTOMIZADA do patrimônio, exclua-a
            if ($caminhoImagemAntigaNoDB &&
                strpos($caminhoImagemAntigaNoDB, UPLOAD_URL_PATRIMONIO) === 0 && // Verifica se era uma imagem customizada
                (basename($caminhoImagemAntigaNoDB) !== 'default_patrimonio.png') &&
                file_exists(UPLOAD_DIR_PATRIMONIO . basename($caminhoImagemAntigaNoDB))) {
                
                unlink(UPLOAD_DIR_PATRIMONIO . basename($caminhoImagemAntigaNoDB));
                error_log("DEBUG: Imagem antiga de patrimônio customizada removida (usando imagem do novo modelo): " . UPLOAD_DIR_PATRIMONIO . basename($caminhoImagemAntigaNoDB));
            }
        }
        // Se nenhuma das condições acima for atendida, $shouldUpdateImageColumn permanece false,
        // e a imagem_patrimonio do DB não será alterada, mantendo o valor existente.


        // 3. Preparar campos para atualização no banco de dados
        $fields_to_update = [];
        $params = [':id_patrimonio' => $id_patrimonio_int];

        $fields_to_update[] = "codigo_patrimonio = :codigo_patrimonio";
        $params[':codigo_patrimonio'] = $codigo_patrimonio;

        $fields_to_update[] = "tipo_patrimonio = :tipo_patrimonio";
        $params[':tipo_patrimonio'] = $tipo_patrimonio;

        $desc_final = (trim($descricao_patrimonio ?? '') === '') ? null : $descricao_patrimonio;
        $fields_to_update[] = "descricao_patrimonio = :descricao_patrimonio";
        $params[':descricao_patrimonio'] = $desc_final;
        
        $fields_to_update[] = "setor_origem_id = :setor_origem_id";
        $params[':setor_origem_id'] = $setor_origem_id;

        $nfe_final = (trim($nfe_patrimonio ?? '') === '') ? null : $nfe_patrimonio;
        $fields_to_update[] = "nfe_patrimonio = :nfe_patrimonio";
        $params[':nfe_patrimonio'] = $nfe_final;

        $lote_final = (trim($lote_patrimonio ?? '') === '') ? null : $lote_patrimonio;
        $fields_to_update[] = "lote_patrimonio = :lote_patrimonio";
        $params[':lote_patrimonio'] = $lote_final;

        $data_aq_final = (trim($dataentrada_patrimonio ?? '') === '') ? null : $dataentrada_patrimonio;
        $fields_to_update[] = "dataentrada_patrimonio = :dataentrada_patrimonio";
        $params[':dataentrada_patrimonio'] = $data_aq_final;

        $fields_to_update[] = "id_modelo = :id_modelo";
        $params[':id_modelo'] = $id_modelo;

        $fields_to_update[] = "id_marca = :id_marca";
        $params[':id_marca'] = $id_marca;

        $fields_to_update[] = "id_fornecedor = :id_fornecedor";
        $params[':id_fornecedor'] = $id_fornecedor;

        $fields_to_update[] = "id_setorAtual = :id_setorAtual";
        $params[':id_setorAtual'] = $id_setorAtual;

        // Incluir o campo da imagem APENAS SE houver uma nova imagem OU se foi sinalizada a mudança do modelo
        if ($shouldUpdateImageColumn) {
            $fields_to_update[] = "imagem_patrimonio = :imagem_patrimonio";
            $params[':imagem_patrimonio'] = $novoCaminhoImagemParaDB;
        }

        // 4. Construir e executar a query de atualização
        $sql = "UPDATE patrimonio SET " . implode(", ", $fields_to_update) . " WHERE id_patrimonio = :id_patrimonio AND deletado_patrimonio = 0";
        $stmt = $conn->prepare($sql);
        
        // Bind dos parâmetros
        foreach ($params as $placeholder => &$value) {
            $type = PDO::PARAM_STR;
            if (strpos($placeholder, ':id_') !== false || strpos($placeholder, ':setor_') !== false) {
                $type = PDO::PARAM_INT;
            } elseif ($value === null) {
                $type = PDO::PARAM_NULL;
            }
            $stmt->bindParam($placeholder, $value, $type);
        }
        unset($value);

        $stmt->execute();
        $affectedRows = $stmt->rowCount();

        // Determinar a URL da imagem a ser retornada na resposta
        $imagemUrlRetorno = $shouldUpdateImageColumn ? $novoCaminhoImagemParaDB : $caminhoImagemAntigaNoDB;

        if ($affectedRows > 0 || $dataChanged || $shouldUpdateImageColumn) { // Considerar sucesso se dados ou imagem foram alterados
            respondeJson('success', 'Patrimônio atualizado com sucesso!', ['id_patrimonio' => $id_patrimonio_int, 'imagem_url' => $imagemUrlRetorno]);
        } else {
            respondeJson('info', 'Nenhuma alteração detectada nos dados do patrimônio.', ['id_patrimonio' => $id_patrimonio_int, 'imagem_url' => $imagemUrlRetorno]);
        }

    } catch (PDOException $e) {
        error_log("Erro PDO ao atualizar patrimônio {$id_patrimonio_int}: " . $e->getMessage());
        // Se houve um erro de DB APÓS o upload da nova imagem, exclua a nova imagem "órfã".
        if ($novoCaminhoImagemParaDB && isset($_FILES['imagem_patrimonio']) && file_exists(UPLOAD_DIR_PATRIMONIO . basename($novoCaminhoImagemParaDB))) {
            unlink(UPLOAD_DIR_PATRIMONIO . basename($novoCaminhoImagemParaDB));
            error_log("DEBUG: Nova imagem órfã de patrimônio removida devido a erro de DB: " . UPLOAD_DIR_PATRIMONIO . basename($novoCaminhoImagemParaDB));
        }

        if (isset($e->errorInfo[1]) && $e->errorInfo[1] == 1062) { // Erro de unicidade (código_patrimonio)
            respondeJson('error_client', 'Erro: Já existe outro patrimônio com este código.');
        } else {
            respondeJson('error_server', 'Erro de banco de dados ao atualizar o patrimônio.');
        }
    } catch (Exception $e) {
        error_log("Erro geral ao atualizar patrimônio {$id_patrimonio_int}: " . $e->getMessage());
        respondeJson('error_server', 'Ocorreu um erro inesperado ao atualizar o patrimônio: ' . $e->getMessage());
    } finally {
        fechaConexaoBD($conn);
    }
}

function inativarPatrimonioPHP($id_patrimonio)
{
    error_log("inativarPatrimonioPHP chamado para ID: $id_patrimonio");

    if (empty($id_patrimonio) || !filter_var($id_patrimonio, FILTER_VALIDATE_INT)) {
        respondeJson('error_client', "ID do patrimônio inválido.");
        return;
    }
    $conn = abreConexaoBD();
    try {
        $sql = "UPDATE patrimonio SET deletado_patrimonio = 1 WHERE id_patrimonio = :id_patrimonio AND deletado_patrimonio = 0";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':id_patrimonio', $id_patrimonio, PDO::PARAM_INT);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            respondeJson('success', 'Patrimônio inativado com sucesso.');
        } else {
            respondeJson('info', 'Nenhum patrimônio encontrado com o ID fornecido ou já estava inativado.');
        }
    } catch (PDOException $e) {
        error_log("Erro PDO ao inativar patrimônio {$id_patrimonio}: " . $e->getMessage());
        respondeJson('error_server', 'Erro de banco de dados ao inativar o patrimônio.');
    } finally {
        fechaConexaoBD($conn);
    }
}

function verificarCodigoPatrimonioExistentePHP($codigo_patrimonio)
{
    $conn = abreConexaoBD();

    if (empty($codigo_patrimonio)) {
        respondeJson('error_client', "O código do patrimônio não foi fornecido.");
        return;
    }

    $sql = "SELECT COUNT(*) FROM patrimonio WHERE codigo_patrimonio = :codigo_patrimonio AND deletado_patrimonio = 0";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':codigo_patrimonio', $codigo_patrimonio);
    $stmt->execute();
    $count = $stmt->fetchColumn();

    // Retorna um JSON simples indicando a existência
    echo json_encode(["exists" => ($count > 0)]);
    exit; // Importante para não ter output adicional
}

function verificarCodigoPatrimonioExistenteEdicaoPHP($codigo_patrimonio, $id_patrimonio)
{
    $conn = abreConexaoBD();

    if (empty($codigo_patrimonio) || empty($id_patrimonio)) {
        respondeJson('error_client', "Código do patrimônio ou ID não foram fornecidos para verificação de edição.");
        return;
    }

    $sql = "SELECT COUNT(*)
            FROM patrimonio
            WHERE codigo_patrimonio = :codigo_patrimonio
            AND id_patrimonio != :id_patrimonio
            AND deletado_patrimonio = 0";

    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':codigo_patrimonio', $codigo_patrimonio);
    $stmt->bindParam(':id_patrimonio', $id_patrimonio, PDO::PARAM_INT);
    $stmt->execute();
    $count = $stmt->fetchColumn();

    echo json_encode(["exists" => ($count > 0)]);
    exit; // Importante para não ter output adicional
}


// ===================== Chamada das Funções acima
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    exit;
}


if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    $acao = $_POST['acao'] ?? ($_GET['acao'] ?? null);

    $multipart_actions = [
        'inserirModeloPHP',
        'atualizarModeloPHP',
        'inserirPatrimonioPHP',
        'atualizarPatrimonioPHP'
    ];

    if (in_array($acao, $multipart_actions)) {
        switch ($acao) {
            case 'inserirModeloPHP':
                inserirModeloPHP(
                    $_POST['nome_modelo'] ?? null,
                    $_POST['cor_modelo'] ?? null,
                    $_POST['descricao_modelo'] ?? null
                );
                break;
            case 'atualizarModeloPHP': // <-- NOVO BLOCO AQUI
                $id_modelo = $_POST['id_modelo'] ?? null;
                $nome_modelo = $_POST['nome_modelo'] ?? null;
                $cor_modelo = $_POST['cor_modelo'] ?? null;
                $descricao_modelo = $_POST['descricao_modelo'] ?? null;

                atualizarModeloPHP(
                    $id_modelo,
                    $nome_modelo,
                    $cor_modelo,
                    $descricao_modelo
                );
                break;
                case 'inserirPatrimonioPHP':
                    inserirPatrimonioPHP(
                        $_POST['codigo_patrimonio'] ?? null,
                        $_POST['tipo_patrimonio'] ?? null,
                        $_POST['descricao_patrimonio'] ?? null,
                        $_POST['setor_origem_id'] ?? null,
                        $_POST['nfe_patrimonio'] ?? null,
                        $_POST['lote_patrimonio'] ?? null,
                        $_POST['dataentrada_patrimonio'] ?? null,
                        $_POST['id_modelo'] ?? null,
                        $_POST['id_marca'] ?? null,
                        $_POST['id_fornecedor'] ?? null
                    );
                    break;
            case 'atualizarPatrimonioPHP':
                atualizarPatrimonioPHP(
                    $_POST['id_patrimonio'] ?? null,
                    $_POST['codigo_patrimonio'] ?? null,
                    $_POST['tipo_patrimonio'] ?? null,
                    $_POST['descricao_patrimonio'] ?? null,
                    $_POST['setor_origem_id'] ?? null,
                    $_POST['nfe_patrimonio'] ?? null,
                    $_POST['lote_patrimonio'] ?? null,
                    $_POST['dataentrada_patrimonio'] ?? null, // Recebe do POST
                    $_POST['id_modelo'] ?? null,
                    $_POST['id_marca'] ?? null,
                    $_POST['id_fornecedor'] ?? null,
                    $_POST['id_setorAtual'] ?? null // Este também vem do POST
                    // 'imagem_patrimonio' é tratada dentro da função a partir de $_FILES
                );
                break;
            }
        exit;
    } else {
        $data = json_decode(file_get_contents("php://input"), true) ?? [];
        $acao = $data['acao'] ?? $acao;

    if (!$acao || !in_array($acao, [
        'logarPHP',
        'inserirUsuarioCompletoPHP',
        'listarUsuariosPHP',
        'atualizarUsuarioCompletoPHP',
        'inativarUsuarioPHP',
        'carregarUsuarioPHP',
        'listarModelosPHP',
        'inativarModeloPHP',
        'carregarModeloPHP',
        'verificarNomeModeloExistente',
        'verificarNomeModeloExistenteEdicao',
        'inserirMarca',
        'listarMarcas',
        'atualizarMarca',
        'inativarMarca',
        'carregarMarca',
        'verificarNomeMarcaExistente',
        'verificarNomeMarcaExistenteEdicao',
        'inserirFornecedor',
        'atualizarFornecedor',
        'listarFornecedor',
        'inativarFornecedor',
        'carregarFornecedor',
        'verificarCnpjExistente',
        'verificarCnpjExistenteEdicao',
        'inserirSetor',
        'listarSetor',
        'atualizarSetor',
        'inativarSetor',
        'carregarSetor',
        'verificarSetorExistente',
        'verificarSetorExistenteEdicao',
        'listarPatrimoniosPHP',
        'carregarPatrimonioPHP',
        'inativarPatrimonioPHP',
        'verificarCodigoPatrimonioExistentePHP',
        'verificarCodigoPatrimonioExistenteEdicaoPHP',
        'buscarPatrimoniosParaSelecaoPHP', // Nova ação
        'cadastrarMovimentacaoPHP',        // Nova ação
        'listarMovimentacoesPHP'          // Nova ação
        ])) {
        respondeJson('error', 'Ação inválida.');
    }

    try {
        switch ($acao) {
            case 'logarPHP':
                logarPHP(
                    $data['usuario'] ?? null,
                    $data['senha'] ?? null
                );
                break;
            case 'inserirUsuarioCompletoPHP':
                inserirUsuarioCompletoPHP(
                    $data['nome_usuario'] ?? null,
                    $data['senha_usuario'] ?? null,
                    $data['cpf_usuario'] ?? null,
                    $data['nasc_usuario'] ?? null,
                    $data['tipo_usuario'] ?? null
                );
                break;
            case 'listarUsuariosPHP':
                listarUsuariosPHP(
                    $data['deletado'] ?? 0,
                    $data['filtro_nome_usuario'] ?? null
                );
                break;
            case 'atualizarUsuarioCompletoPHP':
                $id_usuario_update = $data['id_usuario'] ?? null;
                $dados_para_funcao = $data;
                // Remove 'acao' e 'id_usuario' pois são passados separadamente
                unset($dados_para_funcao['acao'], $dados_para_funcao['id_usuario']);
                // Removido 'email_usuario' do unset, pois não é mais esperado
                atualizarUsuarioCompletoPHP($id_usuario_update, $dados_para_funcao);
                break;
            case 'inativarUsuarioPHP':
                inativarUsuarioPHP($data['id_usuario'] ?? null);
                break;
            case 'carregarUsuarioPHP':
                carregarUsuarioPHP($data['id_usuario'] ?? null);
                break;
            case 'listarModelosPHP':
                listarModelosPHP(
                    $data['deletado'] ?? 0,
                    $data['filtro_nome_modelo'] ?? null
                );
                break;
            case 'inativarModeloPHP':
                inativarModeloPHP($data['id_modelo'] ?? null);
                break;
            case 'carregarModeloPHP':
                    carregarModeloPHP($data['id_modelo'] ?? null);
                    break;
            case 'verificarNomeModeloExistente':
                verificarNomeModeloExistente($data['nome_modelo'] ?? null);
                break;
        
            case 'verificarNomeModeloExistenteEdicao':
                verificarNomeModeloExistenteEdicao($data['nome_modelo'] ?? null, $data['id_modelo'] ?? null);
                break;
            case 'inserirMarca':
                inserirMarca($data['nome_marca']);
                break;
            case 'listarMarcas':
                listarMarcas($data['deletado_marca'] ?? 0); // Usando o nome correto do campo
                break;
            case 'atualizarMarca':
                if (empty($data['id_marca']) || empty($data['nome_marca'])) { // Usando os nomes corretos
                    respondeJson('error', "Os campos 'id_marca' e 'nome_marca' são obrigatórios.");
                }
                atualizarMarca($data['id_marca'], $data['nome_marca']); // Usando os nomes corretos
                break;
            case 'inativarMarca':
                if (empty($data['id_marca'])) { // Usando o nome correto
                    respondeJson('error', "O campo 'id_marca' é obrigatório.");
                }
                inativarMarca($data['id_marca']); // Usando o nome correto
                break;
            case 'carregarMarca':
                if (isset($data['id_marca'])) { // Usando o nome correto
                    carregarMarca($data['id_marca']); // Usando o nome correto
                } else {
                    respondeJson('error', 'ID da marca não fornecido.');
                }
                break;
            case 'verificarNomeMarcaExistente':
                verificarNomeMarcaExistente($data['nome_marca'] ?? null);
                break;
            case 'verificarNomeMarcaExistenteEdicao':
                verificarNomeMarcaExistenteEdicao(
                    $data['nome_marca'] ?? null, // Usando o nome correto
                    $data['id_marca'] ?? null // Usando o nome correto
                );
                break;
            case 'inserirFornecedor':
                inserirFornecedor(
                    $data['nome'] ?? null,
                    $data['cnpj'] ?? null,
                    $data['contato'] ?? null,
                    $data['endereco'] ?? null
                );
                break;
            case 'atualizarFornecedor':
                atualizarFornecedor(
                    $data['id'] ?? null,
                    $data['nome'] ?? null,
                    $data['cnpj'] ?? null,
                    $data['contato'] ?? null,
                    $data['endereco'] ?? null,
                    $data['deletado'] ?? 0
                );
                break;
            case 'listarFornecedor':
                $deletado = $data['deletado'] ?? 0;
                listarFornecedor($deletado);
                break;
            case 'inativarFornecedor':
                inativarFornecedor($data['id'] ?? null);
                break;
            case 'carregarFornecedor':
                carregarFornecedor($data['id'] ?? null);
                break;
            case 'verificarCnpjExistente':
                verificarCnpjExistente($data['cnpj'] ?? null);
                break;
            case 'verificarCnpjExistenteEdicao':
                verificarCnpjExistenteEdicao($data['cnpj'] ?? null, $data['id'] ?? null);
                break;
            case 'inserirSetor':
                inserirSetor(
                    $data['tipo_setor'] ?? null,
                    $data['nome_setor'] ?? null,
                    $data['responsavel_setor'] ?? null,
                    $data['descricao_setor'] ?? null,
                    $data['contato_setor'] ?? null,
                    $data['email_setor'] ?? null
                );
                break;
            case 'listarSetor':
                listarSetor(
                    $data['deletado_setor'] ?? 0,
                    $data['nome_setor'] ?? null,
                    $data['tipo_setor'] ?? null
                );
                break;
            case 'atualizarSetor':
                atualizarSetor(
                    $data['id_setor'] ?? null,
                    $data['tipo_setor'] ?? null,
                    $data['nome_setor'] ?? null,
                    $data['responsavel_setor'] ?? null,
                    $data['descricao_setor'] ?? null,
                    $data['contato_setor'] ?? null,
                    $data['email_setor'] ?? null
                );
                break;
            case 'inativarSetor':
                inativarSetor($data['id_setor'] ?? null);
                break;
            case 'carregarSetor':
                carregarSetor($data['id_setor'] ?? null);
                break;
            case 'verificarSetorExistente':
                verificarSetorExistente($data['nome_setor'] ?? null);
                break;
            case 'verificarSetorExistenteEdicao':
                verificarSetorExistenteEdicao(
                    $data['nome_setor'] ?? null,
                    $data['id_setor'] ?? null
                );
                break;
            case 'listarPatrimoniosPHP':
                listarPatrimoniosPHP(
                    $data['page'] ?? 1,
                    $data['limit'] ?? 10,
                    $data['deletado'] ?? 0,
                    $data['filtros'] ?? []
                );
                break;
            case 'carregarPatrimonioPHP':
                carregarPatrimonioPHP($data['id_patrimonio'] ?? null);
                break;
            case 'inativarPatrimonioPHP':
                inativarPatrimonioPHP($data['id_patrimonio'] ?? null);
                break;
            case 'verificarCodigoPatrimonioExistentePHP':
                verificarCodigoPatrimonioExistentePHP($data['codigo_patrimonio'] ?? null);
                break;
            case 'verificarCodigoPatrimonioExistenteEdicaoPHP':
                verificarCodigoPatrimonioExistenteEdicaoPHP(
                    $data['codigo_patrimonio'] ?? null,
                    $data['id_patrimonio'] ?? null
                );
                break;
            case 'buscarPatrimoniosParaSelecaoPHP':
                buscarPatrimoniosParaSelecaoPHP(
                    $data['termo'] ?? null
                );
                break;

            case 'cadastrarMovimentacaoPHP':
                cadastrarMovimentacaoPHP(
                    $data['patrimonio_id'] ?? null,
                    $data['origem_setor_id'] ?? null,    // Pode ser null para ENTRADA
                    $data['destino_setor_id'] ?? null,   // Pode ser null para DESCARTE
                    $data['data_movimentacao'] ?? null,  // Formato 'YYYY-MM-DDTHH:MM:SS'
                    $data['tipo_movimentacao'] ?? null,
                    $data['observacao'] ?? null,
                    $data['id_usuario_responsavel'] ?? null // LEMBRETE: Idealmente, pegar do token/sessão no backend
                );
                break;

            case 'listarMovimentacoesPHP':
    // Os filtros são passados como um objeto 'filtros' no corpo da requisição JSON
    // ou como parâmetros GET individuais se preferir ajustar o service no Dart.
    // O MovimentacaoController já monta o objeto de filtros.
                    $filtros_mov = $data; // Todos os dados de $data podem ser os filtros
                    unset($filtros_mov['acao']); // Remove a chave 'acao' se presente
                    listarMovimentacoesPHP($filtros_mov);
                    break;
    default:
    respondeJson('error', 'Ação inválida ou não especificada.');
        }
    } catch (Exception $e) {
        respondeJson('error', 'Erro interno no servidor: ' . $e->getMessage());
    }
}
}