<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Adicione esses cabeçalhos ao seu script PHP
header("Access-Control-Allow-Origin: *"); // Permite requisições de qualquer origem
header("Access-Control-Allow-Credentials: true");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

function abreConexaoBD() {
    $nomeServidor = "localhost";
    $nomeusuarios = "root";
    $senhaAcesso = "";
    $nomeBanco = "cadastro";

    try {
        $conn = new PDO("mysql:host=$nomeServidor;dbname=$nomeBanco", $nomeusuarios, $senhaAcesso);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $conn;
    } catch (PDOException $e) {
        echo json_encode(['status' => 'error', 'message' => 'Falha ao iniciar conexão com o BD: ' . $e->getMessage()]);
        exit();
    }
}

function criaUsuarios($usuario, $senha) {
    $conn = abreConexaoBD();
    $sql = "INSERT INTO usuario (usuario, senha) VALUES (:usuario, :senha)";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':usuario', $usuario);
    $stmt->bindParam(':senha', $senha);
    
    if ($stmt->execute()) {
        echo json_encode(['status' => 'success', 'message' => 'Registro criado com sucesso!']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Erro no processo de criação.']);
    }
}

function inserirDados($marca, $modelo, $cor, $codigo, $data, $fotoBase64) {
    $conn = abreConexaoBD();
    $fotoNome = uniqid() . '.png';
    $fotoCaminho = 'imagens/' . $fotoNome;

    // Certifique-se de que a pasta 'imagens' exista
    if (!file_exists('imagens')) {
        mkdir('imagens', 0777, true);
    }

    if ($fotoBase64) {
        file_put_contents($fotoCaminho, base64_decode($fotoBase64));
    }

    $sql = "INSERT INTO patrimonio (marca, modelo, cor, codigo, data, imagem) VALUES (:marca, :modelo, :cor, :codigo, :data, :imagem)";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':marca', $marca);
    $stmt->bindParam(':modelo', $modelo);
    $stmt->bindParam(':cor', $cor);
    $stmt->bindParam(':codigo', $codigo);
    $stmt->bindParam(':data', $data);
    $stmt->bindParam(':imagem', $fotoCaminho);

    if ($stmt->execute()) {
        echo json_encode(['status' => 'success', 'message' => 'Dados inseridos com sucesso.']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Erro ao inserir os dados.']);
    }
}

function listaTodosProdutos() {
    $conn = abreConexaoBD();
    $sql = "SELECT * FROM patrimonio";
    $stmt = $conn->prepare($sql);
    $stmt->execute();
    $produtos = $stmt->fetchAll(PDO::FETCH_ASSOC);

       // Se não houver produtos, retornar uma lista vazia
       if (!$produtos) {
        $produtos = [];
    }

    echo json_encode(['status' => 'success', 'produtos' => $produtos]);
}

function apagaDadosPatrimonio($id) {
    $conn = abreConexaoBD();
    $sql = "DELETE FROM patrimonio WHERE id = :id";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':id', $id);

    if ($stmt->execute()) {
        echo json_encode(['status' => 'success', 'message' => 'Filme excluído com sucesso.']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Erro ao excluir o filme.']);
    }
}

function validaUsuarios($usuario, $senha) {
    $conn = abreConexaoBD();
    $sql = "SELECT * FROM usuario WHERE usuario = :usuario";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':usuario', $usuario);
    $stmt->execute();
    $usuario = $stmt->fetch();

    return $usuario && $senha == $usuario['senha'];
}

$data = json_decode(file_get_contents("php://input"), true);

if (isset($data['comando'])) {
    switch ($data['comando']) {
        case "logar":
            if (validaUsuarios($data['usuario'], $data['senha'])) {
                echo json_encode(['status' => 'success', 'message' => 'Login OK']);
            } else {
                echo json_encode(['status' => 'error', 'message' => 'Nao foi possível fazer login']);
            }
            break;

        case "cadastra":
            criaUsuarios($data['usuario'], $data['senha']);
            break;

        case "inserir":
            inserirDados(
                $data['marca'],
                $data['modelo'],
                $data['cor'],
                $data['codigo'],
                $data['data'],
                $data['foto']
            );
            break;

        case "listar":
            listaTodosProdutos();
            break;

        case "deletar":
            apagaDadosPatrimonio($data['id']);
            break;

        default:
            echo json_encode(['status' => 'error', 'message' => 'Comando não reconhecido!']);
            break;
    }
} else {
    echo json_encode(['status' => 'error', 'message' => 'Nenhum comando fornecido!']);
}
?>
