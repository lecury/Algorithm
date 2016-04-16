/*
 * Author : Liu Chang
 * Date   : 2016.04.17
 *
 * 掷骰子算法，即给定一频率分布P(p1, p2, ... , pn) 
 * 生成对应的样本，常用在统计模拟中
 */

#include <stdio.h>
#include <random.h>

/*
 * 输入：概率分布
 * 输出：生成的样本
 *
 */
int dice( double probe[], int size )
{
	double pro[size];
	int i = 0;

	for( i = 1; i < size; i++ )
		pro[i] += pro[i-1];

	double priot = ((double)random() / RAND_MAX) * pro[size - 1];

	for( i = 0; i < size; i++ )
	{
		if( pro[i] > priot ) 
			return i;
	}
}
