/* C-Implementation of the Algorithm described in Appendix J of GSM TS 44.018,
 * (C) 2009 by Dirk Hakkesteegt <dirk@hakkesteegt.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
/* Annex J.3 indicates that at least in one BA list, we can never have more
 * than 29 frequencies within the 16byte limit */
#define MAX_ARRFCNS	29

/*****************************************************************************
*        NAME : smod
* DESCRIPTION : n smod m indicates the offset remainder of the euclidian 
*				division of n by m
*       INPUT : n, m
*      OUTPUT : n smod m
*     RETURNS : 
*  Errorcodes : 
******************************************************************************/
static int smod(int n, int m)
{
	int result = n % m;
	if (result < 0)
		result += m;

	if (result == 0)
		result = m;

	return result;
}

/*****************************************************************************
*        NAME : mod
* DESCRIPTION : n mod m indicates the remainder of the euclidian division of
*				n by m
*       INPUT : n, m
*      OUTPUT : n mod m
*     RETURNS : 
*  Errorcodes : 
******************************************************************************/
static int mod(int n, int m)
{
	int result = n % m;
	if (result < 0) 
		result += m;

	return result;
}

/*****************************************************************************
*        NAME : greatest_power_of_2_le_to
* DESCRIPTION : Calculates the greatest power of 2 that is lesser or equal
*				to the input value;
*       INPUT : 
*      OUTPUT : 
*     RETURNS : 
*  Errorcodes : 
******************************************************************************/
static int greatest_power_of_2_le_to(int input)
{
	int check_val = 1;
	while (check_val <= input)
		check_val *= 2;

	return check_val / 2;
}

/*****************************************************************************
*        NAME : ENCODE_SUBTREE
* DESCRIPTION : Recursive encoding routine based on 3GPP TS44.018 Annex J.4
*       INPUT : index: current position in the W list
*				set: the array to be encoded
*				range: the current range
*				set_size: number of elements in set
*      OUTPUT : W: the array of results
*     RETURNS : 
*  Errorcodes : 
******************************************************************************/
static void encode_subtree(int index, int *set, int range, int set_size, int *W)
{
	int index_in_set = 0;
	int N, J, I, x;
	int subset[18];
	int subset_index, origin_value;

	/* Check if this is a leaf */
	if (set_size == 0) {
		W[index] = 0;
		return;
	} else {
		if (set_size == 1) {
			W[index] = 1 + set[1];
			return;
		}
	}

	for (I = 1; I <= set_size; I++) {
		N = 0;
		for (J = 1; J <= set_size; J++) {
			x = set[J] - set[I];
			x = mod(x, range);
			if (x <= (range-1)/2)
				N++;
		}
		if (N-1 == (set_size-1) / 2) {
			index_in_set = I;
			break;
		}
	}

	W[index] = set[index_in_set] + 1;

	/* Left subset */
	subset[0] = 0;
	origin_value = mod((set[index_in_set] + (range-1) / 2 + 1), range);
	subset_index = 1;
	for (I = 1; I <= set_size; I++) {
		 if (mod((set[I]-origin_value), range) < range/2) {
			 subset[subset_index] = mod((set[I] - origin_value), range);
			 subset_index++;
			 subset[subset_index] = 0;
		 }
	}
	encode_subtree(index + greatest_power_of_2_le_to(index),
			subset, range / 2, subset_index-1, W);

	/* Right subset */
	subset[0] = 0;
	origin_value = mod((set[index_in_set] + 1), range);
	subset_index=1;
	for (I = 1; I<= set_size; I++) {
		if (mod((set[I]-origin_value), range) < range/2) {
			subset[subset_index] = mod((set[I] - origin_value), range);
			subset_index++;
			subset[subset_index] = 0;
		}
	}
	encode_subtree(index + 2*greatest_power_of_2_le_to(index),
			subset, (range-1)/2, subset_index-1, W);
}

/*****************************************************************************
*        NAME : CalcARFCN
* DESCRIPTION :	Calculate the ARFCN list
*       INPUT : F: the list of input frequencies. MUST BE SORTED!
*				count: the number of elements in the F list
*				range: the encoding range (default: range 512)
*      OUTPUT : W: the list of W values
*     RETURNS : 
*  Errorcodes : 
******************************************************************************/
static void CalcARFCN(const unsigned int *F, int *W, unsigned int count, unsigned int range)
{
	int i;
	int Fd[MAX_ARFCNS+1];

	W[0] = F[0];
	for (i = 1; i < count; i++) {
		Fd[i] = F[i] - F[0] - 1;
	}
	encode_subtree(1, Fd, range-1, count-1, W);
}

int bitvec2arfcn_list_range(uint8_t *range, struct bitvec *bv, uint16_t range)
{
	unsigned int i, idx = 0;
	int F[MAX_ARFCNS+1];	
	int W[MAX_ARFCNS+1];

	/* build an array of integers from the bitmask */
	for (i = 0; i < bv->data_len*8; i++) {
		if (bitvec_get_bit_pos(bv, i))
			F[idx++] = i;
	}
	/* Perform the actual algorithm to calculate the 'W' values */
	CalcARFCN(F, W, idx, range);

	/* FIXME: Encode the 'W' values into the actual format as used in 04.08 */

	return -EIO;
}
