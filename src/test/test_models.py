import google.generativeai as genai
import os

key = os.getenv('GOOGLE_API_KEY')
if not key:
    print('ERRO: GOOGLE_API_KEY nao encontrada.')
    exit(1)

genai.configure(api_key=key)

print('=== MODELOS DISPONIVEIS ===')
try:
    for m in genai.list_models():
        if 'gemini' in m.name:
            print(f'NOME: {m.name}')
            print(f'METODOS: {m.supported_generation_methods}')
            print('-' * 20)
except Exception as e:
    print(f'ERRO DE CONEXAO: {e}')
    print('DICA: Verifique se a API Generative Language esta ativada no Google Cloud Console.')