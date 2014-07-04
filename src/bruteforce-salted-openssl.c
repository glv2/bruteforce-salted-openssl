/*
Bruteforce a file encrypted (with salt) by openssl.

Copyright 2014 Guillaume LE VAILLANT

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <ctype.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "version.h"

unsigned char *default_charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
unsigned char *charset = NULL, *data = NULL, salt[8], *prefix = NULL, *suffix = NULL;
unsigned int charset_len = 62, data_len = 0, min_len = 1, max_len = 8, prefix_len = 0, suffix_len = 0;
const EVP_CIPHER *cipher = NULL;
const EVP_MD *digest = NULL;
pthread_mutex_t found_password_lock;
char stop = 0, only_one_password = 0;


/*
 * Decryption
 */

int valid_data(unsigned char *data, unsigned int len)
{
  unsigned int i;
  unsigned char c;
  unsigned int bad = 0;

  /* Count the number of not printable characters */
  for(i = 0; i < len; i++)
    {
      c = data[i];
      if(!isprint(c))
        bad++;
    }

  /* Consider the decrypted data as invalid if there is more than 10% of not printable characters */
  if(bad > len / 10)
    return(0);
  else
    return(1);
}

/* The decryption_func thread function tests all the passwords of the form:
 *   prefix + x + combination + suffix
 * where x is a character in the range charset[arg[0]] -> charset[arg[1]]. */
void * decryption_func(void *arg)
{
  unsigned char *password, *key, *iv, *out;
  unsigned int password_len, index_start, index_end, len, out_len1, out_len2, i, j, k;
  int ret;
  unsigned int *tab;
  EVP_CIPHER_CTX ctx;

  index_start = ((unsigned int *) arg)[0];
  index_end = ((unsigned int *) arg)[1];
  key = (unsigned char *) malloc(EVP_CIPHER_key_length(cipher));
  iv = (unsigned char *) malloc(EVP_CIPHER_iv_length(cipher));
  out = (unsigned char *) malloc(data_len + EVP_CIPHER_block_size(cipher));
  if((key == NULL) || (iv == NULL) || (out == NULL))
    {
      fprintf(stderr, "Error: memory allocation failed.\n\n");
      exit(EXIT_FAILURE);
    }

  /* For every possible length */
  for(len = min_len - prefix_len - 1 - suffix_len; len + 1 <= max_len - prefix_len - suffix_len; len++)
    {
      /* For every first character in the range we were given */
      for(k = index_start; k <= index_end; k++)
        {
          password_len = prefix_len + 1 + len + suffix_len;
          password = (unsigned char *) malloc(password_len + 1);
          tab = (unsigned int *) malloc((len + 1) * sizeof(unsigned int));
          if((password == NULL) || (tab == NULL))
            {
              fprintf(stderr, "Error: memory allocation failed.\n\n");
              exit(EXIT_FAILURE);
            }
          strncpy(password, prefix, prefix_len);
          password[prefix_len] = charset[k];
          strncpy(password + prefix_len + 1 + len, suffix, suffix_len);
          password[password_len] = '\0';

          for(i = 0; i <= len; i++)
            tab[i] = 0;

          /* Test all the combinations */
          while((tab[len] == 0) && (stop == 0))
            {
              for(i = 0; i < len; i++)
                password[prefix_len + 1 + i] = charset[tab[len - 1 - i]];

              /* Decrypt data with password */
              EVP_BytesToKey(cipher, digest, salt, password, password_len, 1, key, iv);
              EVP_DecryptInit(&ctx, cipher, key, iv);
              EVP_DecryptUpdate(&ctx, out, &out_len1, data, data_len);
              ret = EVP_DecryptFinal(&ctx, out + out_len1, &out_len2);
              if((ret == 1) && valid_data(out, out_len1 + out_len2))
                {
                  /* We have a positive result */
                  pthread_mutex_lock(&found_password_lock);
                  printf("Password candidate: %s\n", password);
                  if(only_one_password)
                    stop = 1;
                  pthread_mutex_unlock(&found_password_lock);
                }
              EVP_CIPHER_CTX_cleanup(&ctx);

              if(len == 0)
                break;
              tab[0]++;
              if(tab[0] == charset_len)
                tab[0] = 0;
              j = 0;
              while(tab[j] == 0)
                {
                  j++;
                  tab[j]++;
                  if((j < len) && (tab[j] == charset_len))
                    tab[j] = 0;
                }
            }
          free(tab);
          free(password);
        }
    }

  free(out);
  free(iv);
  free(key);

  pthread_exit(NULL);
}


/*
 * Main
 */

void list_ciphers(const EVP_CIPHER *c, const char *from, const char *to, void *arg)
{
  static char *last = NULL;
  char *current;

  if(c)
    {
      current = (char *) EVP_CIPHER_name(c);
      if(last == NULL)
        last = current;
      else if(strcasecmp(last, current) >= 0)
        return;
      else
        last = current;
      fprintf(stderr, "  %s\n", current);
    }
  else if(from && to)
    {
      current = (char *) from;
      if(last == NULL)
        last = current;
      else if(strcasecmp(last, from) >= 0)
        return;
      else
        last = (char *) from;
      fprintf(stderr, "  %s => %s\n", from, to);
    }
}

void list_digests(const EVP_MD *d, const char *from, const char *to, void *arg)
{
  static char *last = NULL;
  char *current;

  if(d)
    {
      current = (char *) EVP_MD_name(d);
      if(last == NULL)
        last = current;
      else if(strcasecmp(last, current) >= 0)
        return;
      else
        last = current;
      fprintf(stderr, "  %s\n", current);
    }
  else if(from && to)
    {
      current = (char *) from;
      if(last == NULL)
        last = current;
      else if(strcasecmp(last, from) >= 0)
        return;
      else
        last = (char *) from;
      fprintf(stderr, "  %s => %s\n", from, to);
    }
}

void usage(char *progname)
{
  fprintf(stderr, "\nbruteforce-salted-openssl %s\n\n", VERSION_NUMBER);
  fprintf(stderr, "Usage: %s [options] <filename>\n\n", progname);
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -1           Stop the program after finding the first password candidate.\n");
  fprintf(stderr, "  -a           List the available cipher and digest algorithms.\n");
  fprintf(stderr, "  -b <string>  Beginning of the password.\n");
  fprintf(stderr, "                 default: \"\"\n");
  fprintf(stderr, "  -c <cipher>  Cipher for decryption.\n");
  fprintf(stderr, "                 default: aes-256-cbc\n");
  fprintf(stderr, "  -d <digest>  Digest for key and initialization vector generation.\n");
  fprintf(stderr, "                 default: md5\n");
  fprintf(stderr, "  -e <string>  End of the password.\n");
  fprintf(stderr, "                 default: \"\"\n");
  fprintf(stderr, "  -h           Show help and quit.\n");
  fprintf(stderr, "  -l <length>  Minimum password length (beginning and end included).\n");
  fprintf(stderr, "                 default: 1\n");
  fprintf(stderr, "  -m <length>  Maximum password length (beginning and end included).\n");
  fprintf(stderr, "                 default: 8\n");
  fprintf(stderr, "  -s <string>  Password character set.\n");
  fprintf(stderr, "                 default: \"0123456789ABCDEFGHIJKLMNOPQRSTU\n");
  fprintf(stderr, "                           VWXYZabcdefghijklmnopqrstuvwxyz\"\n");
  fprintf(stderr, "  -t <n>       Number of threads to use.\n");
  fprintf(stderr, "                 default: 1\n");
  fprintf(stderr, "\n");
}

void list_algorithms(void)
{
  fprintf(stderr, "Available ciphers:\n");
  EVP_CIPHER_do_all_sorted(list_ciphers, NULL);
  fprintf(stderr, "\nAvailable digests:\n");
  EVP_MD_do_all_sorted(list_digests, NULL);
  fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
  unsigned int nb_threads = 1;
  pthread_t *decryption_threads;
  char *filename;
  unsigned int **indexes;
  int fd, i, ret, c;
  struct stat file_stats;

  OpenSSL_add_all_algorithms();

  /* Get options and parameters */
  opterr = 0;
  while((c = getopt(argc, argv, "1ab:c:d:e:hl:m:s:t:")) != -1)
    switch(c)
      {
      case '1':
        only_one_password = 1;
        break;

      case 'a':
        list_algorithms();
        exit(EXIT_FAILURE);
        break;

      case 'b':
        prefix = optarg;
        break;

      case 'c':
        cipher = EVP_get_cipherbyname(optarg);
        if(cipher == NULL)
          {
            fprintf(stderr, "Error: unknown cipher: %s.\n\n", optarg);
            exit(EXIT_FAILURE);
          }
        break;

      case 'd':
        digest = EVP_get_digestbyname(optarg);
        if(digest == NULL)
          {
            fprintf(stderr, "Error: unknown digest: %s.\n\n", optarg);
            exit(EXIT_FAILURE);
          }
        break;

      case 'e':
        suffix = optarg;
        break;

      case 'h':
        usage(argv[0]);
        exit(EXIT_FAILURE);
        break;

      case 'l':
        min_len = (unsigned int) atoi(optarg);
        break;

      case 'm':
        max_len = (unsigned int) atoi(optarg);
        break;

      case 's':
        charset = optarg;
        break;

      case 't':
        nb_threads = (unsigned int) atoi(optarg);
        if(nb_threads == 0)
          nb_threads = 1;
        break;

      default:
        usage(argv[0]);
        switch(optopt)
          {
          case 'b':
          case 'c':
          case 'd':
          case 'e':
          case 'l':
          case 'm':
          case 's':
          case 't':
            fprintf(stderr, "Error: missing argument for option: '-%c'.\n\n", optopt);
            break;

          default:
            fprintf(stderr, "Error: unknown option: '%c'.\n\n", optopt);
            break;
          }
        exit(EXIT_FAILURE);
        break;
      }

  if(optind >= argc)
    {
      usage(argv[0]);
      fprintf(stderr, "Error: missing filename.\n\n");
      exit(EXIT_FAILURE);
    }

  filename = argv[optind];

  /* Check variables */
  if(cipher == NULL)
    cipher = EVP_aes_256_cbc();
  if(digest == NULL)
    digest = EVP_md5();
  if(prefix == NULL)
    prefix = "";
  prefix_len = strlen(prefix);
  if(suffix == NULL)
    suffix = "";
  suffix_len = strlen(suffix);
  if(charset == NULL)
    charset = default_charset;
  charset_len = strlen(charset);
  if(charset_len == 0)
    {
      fprintf(stderr, "Error: charset must have at least one character.\n\n");
      exit(EXIT_FAILURE);
    }
  if(nb_threads > charset_len)
    {
      fprintf(stderr, "Warning: number of threads (%u) bigger than character set length (%u). Only using %u threads.\n\n", nb_threads, charset_len, charset_len);
      nb_threads = charset_len;
    }
  if(min_len < prefix_len + suffix_len + 1)
    {
      fprintf(stderr, "Warning: minimum length (%u) isn't bigger than the length of specified password characters (%u). Setting minimum length to %u.\n\n", min_len, prefix_len + suffix_len, prefix_len + suffix_len + 1);
      min_len = prefix_len + suffix_len + 1;
    }
  if(max_len < min_len)
    {
      fprintf(stderr, "Warning: maximum length (%u) is smaller than minimum length (%u). Setting maximum length to %u.\n\n", max_len, min_len, min_len);
      max_len = min_len;
    }

  /* Check header */
  fd = open(filename, O_RDONLY);
  if(fd == -1)
    {
      perror("open file");
      exit(EXIT_FAILURE);
    }
  memset(salt, 0, sizeof(salt));
  ret = read(fd, salt, 8);
  if(strncmp(salt, "Salted__", 8) != 0)
    {
      close(fd);
      fprintf(stderr, "Error: %s is not a salted openssl file.\n\n", filename);
      exit(EXIT_FAILURE);
    }

  /* Read salt */
  ret = read(fd, salt, 8);
  if(ret != 8)
    {
      close(fd);
      fprintf(stderr, "Error: could not read salt.\n\n");
      exit(EXIT_FAILURE);
    }

  /* Read encrypted data */
  ret = fstat(fd, &file_stats);
  data_len = file_stats.st_size - 16;
  data = (char *) malloc(data_len);
  if(data == NULL)
    {
      fprintf(stderr, "Error: memory allocation failed.\n\n");
      exit(EXIT_FAILURE);
    }
  for(i = 0; i < data_len;)
    {
      ret = read(fd, data + i, data_len - i);
      if(ret == -1)
        {
          close(fd);
          fprintf(stderr, "Error: could not read data.\n\n");
          exit(EXIT_FAILURE);
        }
      else if(ret > 0)
        i += ret;
    }
  close(fd);

  pthread_mutex_init(&found_password_lock, NULL);
  
  /* Start decryption threads */
  decryption_threads = (pthread_t *) malloc(nb_threads * sizeof(pthread_t));
  indexes = (unsigned int **) malloc(nb_threads * sizeof(unsigned int *));
  if((decryption_threads == NULL) || (indexes == NULL))
    {
      fprintf(stderr, "Error: memory allocation failed.\n\n");
      exit(EXIT_FAILURE);
    }
  for(i = 0; i < nb_threads; i++)
    {
      indexes[i] = (unsigned int *) malloc(2 * sizeof(unsigned int));
      if(indexes[i] == NULL)
        {
          fprintf(stderr, "Error: memory allocation failed.\n\n");
          exit(EXIT_FAILURE);
        }
      indexes[i][0] = i * (charset_len / nb_threads);
      if(i == nb_threads - 1)
        indexes[i][1] = charset_len - 1;
      else
        indexes[i][1] = (i + 1) * (charset_len / nb_threads) - 1;
      ret = pthread_create(&decryption_threads[i], NULL, &decryption_func, indexes[i]);
      if(ret != 0)
        {
          perror("decryption thread");
          exit(EXIT_FAILURE);
        }
    }

  for(i = 0; i < nb_threads; i++)
    {
      pthread_join(decryption_threads[i], NULL);
      free(indexes[i]);
    }
  free(indexes);
  free(decryption_threads);
  pthread_mutex_destroy(&found_password_lock);
  free(data);
  EVP_cleanup();

  exit(EXIT_SUCCESS);
}
