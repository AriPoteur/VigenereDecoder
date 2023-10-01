from collections import Counter
from time import time

IC_MONO_FR = 0.0746
IC_POLY = 0.0380

french_alphabet_letter_freq = {
    "a" : round(0.76/100,4),
    "b" : round(0.90/100,4),
    "c" : round(3.26/100,4),
    "d" : round(3.67/100,4),
    "e" : round(14.71/100,4),
    "f" : round(1.06/100,4),
    "g" : round(0.87/100,4),
    "h" : round(0.74/100,4),
    "i" : round(7.53/100,4),
    "j" : round(0.61/100,4),
    "k" : round(0.07/100,4),
    "l" : round(5.46/100,4),
    "m" : round(2.97/100,4),
    "n" : round(7.10/100,4),
    "o" : round(5.80/100,4),
    "p" : round(2.52/100,4),
    "q" : round(1.36/100,4),
    "r" : round(6.70/100,4),
    "s" : round(7.95/100,4),
    "t" : round(7.24/100,4),
    "u" : round(6.31/100,4),
    "v" : round(1.84/100,4),
    "w" : round(0.05/100,4),
    "x" : round(0.43/100,4),
    "y" : round(0.13/100,4),
    "z" : round(0.33/100,4)
}


# Open the ciphertext file and import the text
with open("cipher_text.txt", "r") as f:
    _data = f.read()
# Transform it into lowercase for easier decryption
ciphertext = _data.lower()
# Clean ciphertext from special character, as they are not influenced by the cipher

ciphertext_cleaned = ciphertext.replace(' ',"").replace('\n',"").replace("'","").replace(",","").replace(".","").replace('"','').replace(":","").replace("1","").replace("9","").replace("5","").replace("0","").replace("?","").replace("ã","").replace("§","").replace("-","").replace("»","")
# print(ciphertext_cleaned)



## Index of coincidence, to determine the length of the key
def ciphertext_freq_and_cleaning(raw_ciphertext):
    ciphertext_character_freq = Counter(raw_ciphertext)
    ciphertext_letter_freq = {}
    #[ciphertext_letter_freq.update({key:value}) for (key, value) in ciphertext_character_freq.items() if ord(key) >= 97 and ord(key) <= 97+26]
    [ciphertext_letter_freq.update({key:value}) for (key, value) in ciphertext_character_freq.items()]
    total_letters = sum(ciphertext_letter_freq.values())
    [ciphertext_letter_freq.update({key:round(value/total_letters,4)}) for key, value in ciphertext_letter_freq.items()]
    return dict(sorted(ciphertext_letter_freq.items(), key=lambda x : x[1], reverse=True)) # => return dict



def coincidence_index(ciphertext_letter_freq):
    index_coincidence_ciphertext = 0
    for value in ciphertext_letter_freq.values():
        index_coincidence_ciphertext += value**2
    # if index_coincidence_ciphertext - IC_POLY <= IC_MONO_FR - index_coincidence_ciphertext:
    #     print("This is probably a polyalphabetic cipher")
    # else:
    #     print("This is probably a monoalphabetic ciper")
    # return dict(sorted(ciphertext_letter_freq.items()))
    return round(index_coincidence_ciphertext, 4) # return float

# print(coincidence_index(ciphertext_freq_and_cleaning(ciphertext_cleaned)))


def ciphertext_parser(ciphertext_cleaned, nb_groups):
    ciphertext_parse_array = []
    for i in range(nb_groups):
        tmp_string = ""
        for j in range(i, len(ciphertext_cleaned), nb_groups):
            tmp_string += ciphertext_cleaned[j]
        ciphertext_parse_array.append(tmp_string)
        tmp_string = ""
    return ciphertext_parse_array # return array


# print(ciphertext_parser(ciphertext_cleaned, 9))

# IC_MONO_FR is used because a polyalphabetic cipher is just a monoalphabetic cipher in 2D, meaning that every letter is cipher by a monoalphabetic cipher with a letter from the key
def key_length_finder(ciphertext_parsed_array): 
    group_ic = []
    for i in ciphertext_parsed_array:
        group_ic.append(coincidence_index(ciphertext_freq_and_cleaning(i)))
    average_ic = 0
    average_ic = round(sum(group_ic)/len(group_ic), 4)
    return round(abs(average_ic-IC_MONO_FR), 4)

ic_differences = [key_length_finder(ciphertext_parser(ciphertext_cleaned, i)) for i in range(1,48)]
key_length = ic_differences.index(min(ic_differences))+1
print("The possible key length is:", key_length)

# print("Execution duration (in sec):", round(end-start, 4))


# #############################################

# ## Cracking the key
def parser_in_block(ciphertext_cleaned, key_length):
    ciphertext_blocks = []
    tmp_string = ""
    for i in range(0,len(ciphertext_cleaned), key_length):
        tmp_string += ciphertext_cleaned[i:i+key_length]
        ciphertext_blocks.append(tmp_string)
        tmp_string = ""
    return ciphertext_blocks

    
def frequency_attack(ciphertext_blocks, lang_alphabet_freq):
    nth_character_of_each_block = []
    tmp_string = ""
    for i in range(key_length):
        for l in range(len(ciphertext_blocks)-1):
            tmp_string += ciphertext_blocks[l][i]
        nth_character_of_each_block.append(tmp_string)
        tmp_string = ""
    for i in nth_character_of_each_block:
        print(ciphertext_freq_and_cleaning(i), sum(ciphertext_freq_and_cleaning(i).values()))
        print(dict(sorted(lang_alphabet_freq.items(), key=lambda x : x[1], reverse=True)))
        print("\n")



frequency_attack(parser_in_block(ciphertext_cleaned,key_length),french_alphabet_letter_freq)






# print(coincidence_index(ciphertext))



# def rearrange_ciphertext(ciphertext):
#     coincidence_texts = []
#     for i in range(120):
#         coincidence_texts.append([ciphertext[:-i]])
#     return coincidence_texts

# coincidence_texts_array = rearrange_ciphertext(ciphertext)

# for i in coincidence_texts_array:
#     i[0] = i[0].replace(" ","")
#     i[0] = i[0].replace("'","")
#     i[0] = i[0].replace(".","")
#     i[0] = i[0].replace(",","")
#     i[0] = i[0].replace('"',"")
#     i[0] = i[0].replace('\n',"")
#     i[0] = i[0].replace(':',"")

# cleaned_ciphertexts_array = []
# [cleaned_ciphertexts_array.append(x) for x in coincidence_texts_array if x not in cleaned_ciphertexts_array and x != ['']]


# def key_length_determination(text_array):
#     reference_text = text_array[0][0]
#     hit_same_letter = []
#     strt_index = 1
#     for i in range(1,len(text_array)):
#         counter = 0
#         #print("CURRENT STEP #",i)
#         for j in range(len(text_array[i][0])):
#             if reference_text[strt_index+j] == text_array[i][0][j]:
#                 counter += 1
#                 #print(reference_text[1+j],"=",text_array[i][0][j])
#         hit_same_letter.append(counter)
#         strt_index += 1
#     return hit_same_letter

# coincidences = key_length_determination(cleaned_ciphertexts_array)

# maxes_indexes = []
# copy_coincidences = coincidences

# treshold_freq = 5

# for i in range(treshold_freq):
#     # print("current max coicidences index:",copy_coincidences.index(max(copy_coincidences)))
#     curr_max = max(copy_coincidences)
#     curr_max_index = copy_coincidences.index(max(copy_coincidences))
#     # print("current max:",max(copy_coincidences))
#     maxes_indexes.append([curr_max_index,curr_max])
#     copy_coincidences[curr_max_index] = -1
#     # print(maxes_indexes)
# maxes_indexes.sort()
# average = 0
# for i in range(treshold_freq - 1):
#     average += maxes_indexes[i+1][0] - maxes_indexes[i][0]
# key_length = average/treshold_freq

# #print("KEY LENGTH ==>", key_length)





# def frequency_of_letters(ciphertext_cleaned):
#     return Counter(ciphertext_cleaned)

# # print("CIPHERTEXT LETTER FREQUENCY ==>",frequency_of_letters(cleaned_ciphertexts_array[0][0]))


# def most_probable_letter(ref_dict, dict_to_analyze):
#     sum_end_values = []
#     for i in ref_dict:
#         pass

# def cracking_key(ciphertext_cleaned, dictionary, key_length):
#     tmp_cipher_alphabet = []
#     tmp_list = []
#     for k in range(int(key_length)):
#         for i in range(k,len(ciphertext_cleaned), int(key_length)):
#             tmp_list.append(ciphertext_cleaned[i])
#         #print("".join(tmp_cipher_alphabet), len(tmp_cipher_alphabet))
#         #print(len(ciphertext_cleaned))
#         tmp_cipher_alphabet.append(tmp_list)
#         tmp_list = []
#     for j in tmp_cipher_alphabet:
#         freq_of_letters_in_ciphertext_parts = frequency_of_letters(j)
#         # a = {k: round(v / sum(freq_of_letters_in_ciphertext_parts.values()), 3) for k,v in freq_of_letters_in_ciphertext_parts.items()}
#         print(dict(sorted(freq_of_letters_in_ciphertext_parts.items(), key=lambda x: x[1], reverse=True)))

    


            
    
# cracking_key(cleaned_ciphertexts_array[0][0], french_alphabet_freq, key_length)
