def merge(lista_regras:list[int], esq:int, meio:int, dir:int):
    n1 = meio - esq + 1
    n2 = dir - meio

    # Copy data to temp vectors L[] and R[]
    lista_esq = lista_regras[esq : esq + n1]
    lista_dir = lista_regras[meio+1 : meio +1+ n2]
    print(lista_regras)
    print(lista_esq, n1)
    print(lista_dir, n2)
    
    i = 0
    j = 0
    k = esq
    while i < n1 and j < n2 :
        
        if lista_esq[i] <= lista_dir[j]:
            lista_regras[k] = lista_esq[i]
            i+=1
        else:
            lista_regras[k] = lista_dir[j]
            j+=1
        k+=1
        

    #Copy the remaining elements of L[], 
    #if there are any
    while i < n1:
        lista_regras[k] = lista_esq[i]
        i+=1
        k+=1
    
    #Copy the remaining elements of R[], 
    #if there are any
    while j < n2:
        lista_regras[k] = lista_dir[j]
        j+=1
        k+=1

def mergeSortRegras(lista_regras:int, esq:int, dir:int):

    if esq >= dir:
        return
    
    meio = int(esq + (dir - esq)/2)
    print(esq, meio, dir)
    mergeSortRegras(lista_regras, esq, meio)
    mergeSortRegras(lista_regras, meio+1, dir)
    merge(lista_regras, esq, meio, dir)

if __name__ == "__main__":
    lista = [ 9 , 3, 4,5, 2,3, 1 ,0]
    mergeSortRegras(lista, 0, len(lista)-1)

    print(lista)